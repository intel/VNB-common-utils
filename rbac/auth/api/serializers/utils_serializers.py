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
import logging
import uuid
from functools import partial

from django.utils.translation import ugettext as _
from rest_framework import serializers
from rest_framework.exceptions import NotFound
from rest_framework.serializers import UUIDField

from auth.api import storage
from auth.api.serializers.rbac_choices import (
    CONSUL_SEP, RESOURCE_TO_RELATION_MAP
)


LOG = logging.getLogger(__name__)

# Custom UUID Validator Field


class CustomUUIDField(UUIDField):
    def to_internal_value(self, value):
        return str(value)


def generate_uuid():
    """Generate a random Version 4(v4) UUID

    Returns:
        str: string format of generated UUID
    """
    # Generate a UUID and convert to a string of hex digits
    return str(uuid.uuid4())


def get_rbac_project_id_by_name(name):
    """Get RBACProject id by given name

    Args:
        name(str): RBACProject name

    Returns:
        str: If RBACProject exists, Name of RBACProject
        None: If RBACProject does not exist or name is ''
    """
    records = storage.plugin.get_records_by_secondary_index(
                RESOURCE_TO_RELATION_MAP['RBACProject'],
                'name',
                name)

    if not records:
        raise NotFound(detail=_("%s with name %s not found" % ('RBACProject',
                                                               name)))

    # There should be just one record with a particular RBACProject name
    assert len(records) == 1

    return records[0]['id']

#
# RBAC Resource Existence check
#


def check_project_name_not_exists(value):
    """Check whether RBACProject with given name does not exist

    Args:
        value (str): name of RBACProject
    """
    if not value:
        raise ValueError("RBACProject Name is blank")
    try:
        get_rbac_project_id_by_name(value)
    except NotFound:
        pass
    else:
        raise serializers.ValidationError(
                {'detail': _("%s with name %s already exists" % ('RBACProject',
                                                                 str(value)))})


def check_username_exists(project_id, value):
    """Check whether RBACUser with given name does not exist

    Args:
        project_id (str): RBACProject id
        value (str): name of RBACUser
    """
    if not value:
        raise ValueError("RBACUser Name is blank")

    relation = CONSUL_SEP.join((RESOURCE_TO_RELATION_MAP['RBACProject'],
                                'id',
                                project_id,
                                RESOURCE_TO_RELATION_MAP['RBACUser']))

    records = storage.plugin.get_records_by_secondary_index(relation,
                                                            'username',
                                                            value)

    if records:
        raise serializers.ValidationError(
                {'detail': _("%s with name %s already exists" % ('RBACUser',
                                                                 str(value)))})


def _check_resource_exists(resource_name, project_id, pk):
    """Check whether RBAC record with primary key pk exits

    Args:
        resource_name (str): record's project name
        project_id (str): RBACProject id
        pk (str): Primary Key of the record

    Raises:
        serializers.ValidationError: When record with pk does not exist

    Returns:
        True, if record with pk exists
    """
    relation = CONSUL_SEP.join((RESOURCE_TO_RELATION_MAP['RBACProject'],
                                'id',
                                project_id,
                                RESOURCE_TO_RELATION_MAP[resource_name]))

    if not storage.plugin.check_key(relation, str(pk)):
        raise serializers.ValidationError(
                _("%s %s does not exist" % (resource_name, str(pk))))


check_project_exists = partial(_check_resource_exists, 'RBACProject')

check_group_exists = partial(_check_resource_exists, 'RBACGroup')

check_role_exists = partial(_check_resource_exists, 'RBACRole')

check_rule_exists = partial(_check_resource_exists, 'RBACRule')

check_user_exists = partial(_check_resource_exists, 'RBACUser')

check_certificate_user_exists = partial(_check_resource_exists,
                                        'RBACCertificateUser')

