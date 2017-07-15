#    Copyright (c) 2016 Intel Corporation.
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from __future__ import unicode_literals
import fnmatch
import json
import logging

import consul
import six
from yapsy.IPlugin import IPlugin

from auth.api.storage_plugin.consul_io import consul_config as cfg
from auth.api.storage_plugin.consul_io.consul_io_utils import(
    consul_key_join, CustomEncoder, str_to_dict
)

LOG = logging.getLogger(__name__)

CONSUL_SEP = '/'


class ConsulIO(IPlugin):
    """This a plugin to store VPN configuration or other data in
    backend with Consul(https://www.consul.io/docs/agent/http/kv.html).
        
       Consul store records in the KV(Key/Value) pair.
       
       The VPN configuration or user data is modelled in KV pair before
       storing in Consul as below:

       Key = relation_name/primary_index_name/primary_index_value
       Value = Record tuple in JSON/str/BLOB format
       
       To illustrate above, consider a relation/table 'ikepolicies'
       with 'id' as primary index. And a record tuple in the relation
       'ikepolicies' as
       below:
    
       { 
         "id":"fc5221be-b9d0-11e5-8338-005056b46cff",
         "name":"ikepolicy_1",
         "version":"v1"
       }

       For the above record, the Consul KV pair will look as:

       Key = ikepolicies/id/fc5221be-b9d0-11e5-8338-005056b46cff

       Value = '{"id":"fc5221be-b9d0-11e5-8338-005056b46cff", 
                 "name":"ikepolicy_1", "version":"v1"}'
       

       Secondary Index(es):
       In addition, to help retrieve the stored record with other than
       primary   index, we also prepare and store additional Consul
       record(s) as below:

       Key = relation_name/secondary_index_name/secondary_index_value/ /
             primary_index_name/primary_index_value
       Value = relation_name/primary_index_name/primary_index_value  
       
       To illustrate this part, suppose one of the secondary index of
       relation 'ikepolicies' is 'name'. Then the KV Pair for this will
       look like below:

       Key = ikepolicies/name/ike_1/id/ /
             fc5221be-b9d0-11e5-8338-005056b46cff
       Value = ikepolicies/id/fc5221be-b9d0-11e5-8338-005056b46cff 
       
       A relation could have multiple secondary indexes. So for every
       record, we store this KV pair for each secondary index.

       Relation Name and Primary and Secondary Index:
       The primary index and secondary index(es) for each relation is
       defined in the consul_config module.

    Note:
       This module uses the Python client of Consul to perform KV
       operations
       (http://python-consul.readthedocs.org/en/latest/)
       Installation : pip install python-consul
    """

    def __init__(self):
        super(ConsulIO, self).__init__()
        self.connection = consul.Consul(host=cfg.CONSUL_HOST,
                                        port=cfg.CONSUL_PORT,
                                        consistency=cfg.CONSUL_CONSISTENCY)
        self._relations = {}

    @property
    def relations(self):
        return self._relations

    @relations.setter
    def relations(self, value):
        self._relations.update(value)

    def create_session(self):
        """Create a Consul session for critical section operations

        Returns:
            session_id (int): id of the Consul session
        """
        lock_key = consul_key_join('CONSUL_LOCK')
        lock_delay = 0  # in seconds
        session_id = self.connection.session.create(lock_delay=lock_delay)
        while not self.connection.kv.put(lock_key, '', acquire=session_id):
                pass
        return session_id

    def destroy_session(self, session_id):
        """Destroy the Consul session

        Args:
            session_id: id of the Consul Session
        """
        self.connection.session.destroy(session_id)

    def put_record(self, relation_name, record):
        """Store a record in Consul

        Args:
            relation_name (unicode): Name of the relation/table
            record (object) : Relation/Table record

        Raises:
            TypeError : If relation_name is not a 'string' type and/or
                record is None
        """
        if not isinstance(relation_name, six.string_types) or (record is None):
            raise TypeError

        self._store_record_in_consul(relation_name, record)

    def get_record(self, relation_name, primary_index_value):
        """Retrieve a record from Consul with the required primary
        index value
        
        Args:
            relation_name (unicode): Name of the relation/table
            primary_index_value (unicode): Primary index(key) value
    
        Returns:
            Empty List ([]) OR A record with matching primary index
            value

        Raises:
            TypeError: If passed arguments are not of 'string' type
        """
        if (not isinstance(relation_name, six.string_types) or
                not isinstance(primary_index_value, six.string_types)):
            raise TypeError

        # Find the Primary Index of the relation
        field = self._get_relation_index(relation_name, 'primary')

        # Prepare the key in the required format
        # e.g. ikepolicies/UUID/fc5221be-b9d0-11e5-8338-005056b46cff
        key = consul_key_join(relation_name, field, primary_index_value)

        # Fetch the record with the prepared key
        consul_index, data = self.connection.kv.get(key)

        if data is not None:
            return self._prepare_record(relation_name, data['Value'])
        else:
            return []

    def get_records_by_secondary_index(self,
                                       relation_name,
                                       secondary_index,
                                       field_value):
        """Retrieve a list of record for a secondary index from a
        relation

        Args:
            relation_name (unicode): Name of the relation/table
            secondary_index (unicode): Required secondary index
            field_value (unicode): Secondary index value

        Returns:
            Empty list ([]) OR list of records with the given secondary
            index value in the relation.

        Raises:
            TypeError: If passed arguments are not of 'string' type
        """
        if (not isinstance(relation_name, six.string_types) or
                not isinstance(secondary_index, six.string_types) or
                not isinstance(field_value, six.string_types)):
            raise TypeError

        # Prepare the key prefix with secondary index in the required
        # format
        # e.g. ikepolicies/name/ike_1
        key = consul_key_join(relation_name, secondary_index, field_value)

        # Find the primary index value for the given secondary index
        # value
        consul_index, data = self.connection.kv.get(key, recurse=True)

        if data is None:
            return []

        primary_index_records = (record['Value'] for record in data if
                                 record['Key'].startswith(key + CONSUL_SEP))

        if primary_index_records is None:
            return []

        records = []
        # Fetch the record with the primary index value
        for primary_index in primary_index_records:
            consul_index, data = self.connection.kv.get(primary_index)
            # Prepare a list of all the Consul records' 'Value' field
            records.append(self._prepare_record(relation_name,
                                                data['Value']))

        return records

    def get_records(self, relation_name):
        """Retrieve list of all records of a relation/table.

        Args:
            relation_name (unicode): Name of the relation/table

        Returns:
            list: All records in the relation.

        Raises:
            TypeError: If passed argument is not of 'string' type
        """
        if not isinstance(relation_name, six.string_types):
            raise TypeError

        # Find the primary index of the relation
        field = self._get_relation_index(relation_name, 'primary')

        # Prepare the prefix of the Consul key in the required format
        # e.g. ikepolicies/UUID/
        key = consul_key_join(relation_name, field) + CONSUL_SEP

        # Retrieve the list of all records from Consul
        # Note : 'recurse=True' option fetches all the record with the
        #   given key prefix
        consul_index, data = self.connection.kv.get(key, recurse=True)

        if data is None:
            return []

        # Prepare a list of all the Consul record 'Value' field
        records = [self._prepare_record(relation_name, record['Value']) for
                   record in data]

        return records

    def delete_record(self, relation_name, record):
        """Delete the given record.

        Args:
            relation_name (unicode): Name of the relation/table
            record (object): Relation/Table record

        Raises:
           RuntimeError: Fail to store data in Consul
           TypeError: If relation_name is not a 'string' type and/or
                record is None
        """
        if not isinstance(relation_name, six.string_types) or (record is None):
            raise TypeError

        # Find the primary index of the relation
        pi = self._get_relation_index(relation_name, 'primary')

        # Prepare the key in the required format   
        key = consul_key_join(relation_name, pi, getattr(record, pi))

        session_id = self.create_session()

        try:

            if self._delete_m2m_references(relation_name, record):
                return

            # Delete the KV pair in Consul
            self.connection.kv.delete(key)

            index, data = self.connection.kv.get(key)
            if data is not None:
                LOG.error("Unable to delete record in Consul")
                raise RuntimeError

            # Also delete the secondary index(es) records from Consul
            si = self._get_relation_index(relation_name, 'secondary')
            if si is None:
                return

            for index in si:
                key = consul_key_join(relation_name,
                                      index,
                                      getattr(record, index),
                                      pi,
                                      getattr(record, pi))

                self.connection.kv.delete(key)

                consul_index, data = self.connection.kv.get(key)
                if data is not None:
                    LOG.error("Unable to delete record in Consul")
                    raise RuntimeError
        finally:
            self.destroy_session(session_id)

    def check_key(self, relation_name, primary_index_value):
        """Check if a value is primary index in the relation/table.

        Args:
            relation_name (unicode): Name of the relation/table
            primary_index_value (unicode): Value of primary key(index)

        Returns:
            (bool): True if a value in primary index, else False

        Raises:
            TypeError: If passed argument is not of 'string' type
            ValueError: If index_type is not 'primary'
        """
        if (not isinstance(relation_name, six.string_types) or
                not isinstance(primary_index_value, six.string_types)):
            raise TypeError

        data = self.get_record(relation_name, primary_index_value)

        if data:
            return True
        else:
            return False

    def put_kv(self, key, value=' '):
        """Store a Key/Value pair in Consul

        Args:
            key (str): Key
            value (str): Value , Defaults to ' '.

        Raises:
            TypeError: If Key or Value is not a 'string' type
            RuntimeError: Fail to store KV in Consul
        """
        if (not isinstance(key, six.string_types) or
                not isinstance(key, six.string_types)):
            raise TypeError

        rvalue = self.connection.kv.put(key, value)

        if rvalue is None:
            LOG.error("Unable to store KV pair in Consul")
            raise RuntimeError

    def get_kv(self, key):
        """Fetch the Value for the  Key in Consul

        Args:
            key (str): Key

        Returns:
            (str): Value

        Raises:
            TypeError: If Key is not a 'string' type
            RuntimeError: Fail to get data from Consul
        """
        if not isinstance(key, six.string_types):
            raise TypeError

        consul_index, data = self.connection.kv.get(key)

        if data is None:
            LOG.error("Unable to get Value for the Key in Consul")
            return None

        return data['Value']

    def delete_kv(self, key, recurse=False):
        """Delete the Key/Value pair for the  Key in Consul

        Args:
            key (str): Key
            recurse(bool): whether delete recursively for with the key prefix

        Raises:
            TypeError: If Key is not a 'string' type
            RuntimeError: Fail to get data from Consul
        """
        if not isinstance(key, six.string_types):
            raise TypeError

        # Delete the KV pair in Consul
        self.connection.kv.delete(key, recurse=recurse)

        index, data = self.connection.kv.get(key, recurse=recurse)

        if data is not None:
            LOG.error("Unable to delete record in Consul")
            raise RuntimeError

    def get_key_prefix(self, key_prefix, keys=False):
        """Fetch the records with the Key prefix in Consul

        Args:
            key_prefix (str): Key Prefix
            keys (bool): If True, only get records' key from consul

        Returns:
            list: List of records

        Raises:
            TypeError: If Key is not a 'string' type
            RuntimeError: Fail to get data from Consul
        """
        if not isinstance(key_prefix, six.string_types):
            raise TypeError

        consul_index, data = self.connection.kv.get(consul_key_join(key_prefix),
                                                    recurse=True,
                                                    keys=keys)

        if data is None:
            return []

        if not keys:
            # Prepare a list of all the Consul record 'Value' field
            records = [record['Value'] for record in data]
        else:
            return data

        return records

    def _store_record_in_consul(self, relation_name, record):
        """Store record in the Consul with primary index(pi) as the
        'key' and the record in JSON format as the 'value'.
 
        Args:
            relation_name (unicode): Name of the relation/table
            record (Any relation record object): Relation/Table
                                                    record
         Raises:
           RuntimeError: Fail to store data in Consul
        """
        session_id = self.create_session()

        try:
            if self._prepare_m2m_references(relation_name, record):
                return

            # Find the primary index of the relation
            pi = self._get_relation_index(relation_name, 'primary')

            # Prepare the key in the required format
            # e.g. ikepolicies/UUID/fc5221be-b9d0-11e5-8338-005056b46cff
            key = consul_key_join(relation_name, pi, getattr(record, pi))

            # Convert the object into JSON(dict)
            value = json.dumps(record.__dict__, cls=CustomEncoder)

            # Store secondary indexes in Consul
            self._prepare_secondary_indices(relation_name, record)

            # Store KV pair in Consul
            rvalue = self.connection.kv.put(key, value)
        finally:
            self.destroy_session(session_id)

        if rvalue is None:
            LOG.error("Unable to store record in Consul")
            raise RuntimeError

    def _prepare_secondary_indices(self, relation_name, record):
        """Store each secondary index of the relation/table along with
        primary index value for the record. The list of secondary
        index is present in the consul_config.
       
       Args:
           relation_name (unicode): Name of the relation/table
           record (Any relation record object): Relation/Table record

       Raises:
           RuntimeError: Fail to store data in Consul
       """
        # Find the primary index of the relation
        pi = self._get_relation_index(relation_name, 'primary')

        # Prepare the Consul value
        value = consul_key_join(relation_name, pi, getattr(record, pi))

        # Find the list of Secondary Index
        si_list = self._get_relation_index(relation_name, 'secondary')
        if si_list is None:
            return

        for si in si_list:
            # Adding primary index value to the key helps in storing
            # multiple values for same index.

            # For update(PUT/PATCH) operation of secondary index(es),
            # first delete the existing secondary index Consul record
            key_prefix = consul_key_join(relation_name, si) + CONSUL_SEP
            key_suffix = CONSUL_SEP.join((pi, getattr(record, pi)))
            consul_index, data = self.connection.kv.get(key_prefix,
                                                        keys=True,
                                                        recurse=True)
            if data is not None:
                regex = key_prefix + CONSUL_SEP.join(('*', key_suffix))
                match_key = fnmatch.filter(data, regex)
                if match_key:
                    self.connection.kv.delete(match_key[0])

            # Store secondary index in Consul
            key = key_prefix + CONSUL_SEP.join((getattr(record, si),
                                                key_suffix))
            rvalue = self.connection.kv.put(key, value)
            if rvalue is None:
                LOG.error("Unable to store secondary index in Consul")
                raise RuntimeError

    def _prepare_m2m_references(self, relation_name, record):
        """Store Many to Many references"""

        m2m_ref_relations = self._get_reference_info(relation_name,
                                                     'many_to_many')

        if not m2m_ref_relations:
            return False

        primary_resource_pi = self._get_relation_index(m2m_ref_relations[0],
                                                       'primary')
        primary_resource_pi_value = getattr(record,
                                            '_'.join((m2m_ref_relations[0],
                                                      primary_resource_pi)))

        secondary_resource_pi = self._get_relation_index(m2m_ref_relations[1],
                                                         'primary')
        secondary_resource_pi_value = getattr(record,
                                              '_'.join((m2m_ref_relations[1],
                                                        secondary_resource_pi)))

        key = consul_key_join(relation_name,
                              primary_resource_pi,
                              primary_resource_pi_value,
                              secondary_resource_pi,
                              secondary_resource_pi_value)

        value = consul_key_join(relation_name.rsplit(CONSUL_SEP, 1)[0],
                                m2m_ref_relations[1],
                                secondary_resource_pi,
                                secondary_resource_pi_value)

        # Store KV pair in Consul
        rvalue = self.connection.kv.put(key, value)

        if rvalue is None:
            LOG.error("Unable to store record in Consul")
            raise RuntimeError

        key = consul_key_join(relation_name,
                              secondary_resource_pi,
                              secondary_resource_pi_value,
                              primary_resource_pi,
                              primary_resource_pi_value)

        value = consul_key_join(relation_name.rsplit(CONSUL_SEP, 1)[0],
                                m2m_ref_relations[0],
                                primary_resource_pi,
                                primary_resource_pi_value)

        # Store KV pair in Consul
        rvalue = self.connection.kv.put(key, value)

        if rvalue is None:
            LOG.error("Unable to store record in Consul")
            raise RuntimeError

        return True

    def _delete_m2m_references(self, relation_name, record):
        m2m_ref_relations = self._get_reference_info(relation_name,
                                                     'many_to_many')

        if not m2m_ref_relations:
            return False

        primary_resource_pi = self._get_relation_index(m2m_ref_relations[0],
                                                       'primary')
        primary_resource_pi_value = getattr(record,
                                            '_'.join((m2m_ref_relations[0],
                                                      primary_resource_pi)))

        secondary_resource_pi = self._get_relation_index(m2m_ref_relations[1],
                                                         'primary')
        secondary_resource_pi_value = getattr(record,
                                              '_'.join((m2m_ref_relations[1],
                                                        secondary_resource_pi)))

        key = consul_key_join(relation_name,
                              primary_resource_pi,
                              primary_resource_pi_value,
                              secondary_resource_pi,
                              secondary_resource_pi_value)

        self.connection.kv.delete(key)

        index, data = self.connection.kv.get(key)
        if data is not None:
            LOG.error("Unable to delete record in Consul")
            raise RuntimeError

        key = consul_key_join(relation_name,
                              secondary_resource_pi,
                              secondary_resource_pi_value,
                              primary_resource_pi,
                              primary_resource_pi_value)

        self.connection.kv.delete(key)

        index, data = self.connection.kv.get(key)
        if data is not None:
            LOG.error("Unable to delete record in Consul")
            raise RuntimeError

        return True

    def _prepare_record(self, relation_name, record):
        record_dict = str_to_dict(record)

        primary_resource_pi = self._get_relation_index(relation_name,
                                                       'primary')
        primary_resource_pi_value = record_dict[primary_resource_pi]

        reference_key_prefix = CONSUL_SEP.join((primary_resource_pi,
                                                primary_resource_pi_value))

        record_dict.update(self._get_m2m_relation_records(
                relation_name,
                reference_key_prefix))

        return record_dict

    def _get_m2m_relation_records(self, relation_name,
                                  reference_key_prefix):
        """Fetch Many to Many records for a relation


        Args:
            relation_name (unicode): Name of the relation/table
            reference_key_prefix (unicode):

        Returns:
            dict: Many to Many records of the relation
        """
        reference_relations = self._get_reference_info(relation_name, 'many')

        m2m_relation_records = {}
        for reference in reference_relations:
            m2m_relations = self._get_reference_info(reference, 'many_to_many')

            assert len(m2m_relations) == 2

            primary_relation = self._get_relation_name(relation_name)
            assert primary_relation in m2m_relations

            if primary_relation == m2m_relations[0]:
                secondary_relation = m2m_relations[1]
            else:
                secondary_relation = m2m_relations[0]
            secondary_resource_pi = self._get_relation_index(secondary_relation,
                                                             'primary')

            m2m_relation_name = relation_name
            relation_name_parts = relation_name.split(CONSUL_SEP)
            if len(relation_name_parts) > 1:
                relation_name_parts[-1] = reference
                m2m_relation_name = CONSUL_SEP.join(relation_name_parts)

            m2m_key_prefix = consul_key_join(m2m_relation_name,
                                             reference_key_prefix,
                                             secondary_resource_pi) + CONSUL_SEP

            consul_index, data = self.connection.kv.get(m2m_key_prefix,
                                                        recurse=True)

            if data is None:
                continue

            # Prepare a list of all the Consul record 'Value' field
            records = [record['Value'] for record in data]

            reference_records = []

            for record in records:
                consul_index, data = self.connection.kv.get(record)

                if data is None:
                    LOG.error("Unable to get Value for the Key in Consul")
                    continue

                reference_records.append(str_to_dict(data['Value']))

            m2m_relation_records[secondary_relation] = reference_records

        return m2m_relation_records

    def _get_relation_index(self, relation_name, index_type):
        """Find the primary index or list of secondary index of
        relation from the consul config file

        Args:
            relation_name (unicode): Name of the relation/table
            index_type (unicode): Type of index = 'primary' or 'secondary'
       
        Returns:
            Primary index or list of secondary index
        """
        relation_name = self._get_relation_name(relation_name)

        index_type = index_type.lower()
        if index_type == 'primary':
            return self.relations[relation_name].get('primary_key')
        elif index_type == 'secondary':
            return self.relations[relation_name].get('secondary_keys', [])
        elif index_type == 'foreign':
            return self.relations[relation_name].get('foreign_keys', [])
        else:
            raise ValueError("Invalid index type")

    def _get_reference_info(self, relation_name, reference_type):
        """Find the primary index or list of secondary index of
        relation from the consul config file

        Args:
            relation_name (unicode): Name of the relation/table
            reference_type (unicode): Type of index = 'primary' or
                'secondary'

        Returns:
            Primary index or list of secondary index
        """
        relation_name = self._get_relation_name(relation_name)

        reference_type = reference_type.lower()
        if reference_type == 'many_to_many':
            return self.relations[relation_name].get(
                    'many_to_many_reference', [])
        elif reference_type == 'many':
            return self.relations[relation_name].get('many_references', [])
        else:
            raise ValueError("Invalid reference type")

    @staticmethod
    def _get_relation_name(key):
        """Extract relation name from the key prefix

        Args:
            key (unicode): Key Prefix with Relation Name

        Returns:
            str: Relation Name
        """
        key_prefix_parts = key.split(CONSUL_SEP)
        if len(key_prefix_parts) > 1:
            relation_name = key_prefix_parts[3]
            return relation_name
        return key
