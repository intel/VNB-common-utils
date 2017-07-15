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
from fnmatch import fnmatch

import netifaces

from rest_framework.exceptions import PermissionDenied

from auth.api.serializers.utils_serializers import get_rbac_project_id_by_name
from auth.api.views_resource import RESOURCES, RESOURCES_FOR_ADD_REMOVE

DELIMITER = '_'


def get_resource_info(endpoint, url_name, **path_kwargs):
    """Get the RBAC Resource and Project information from URI and path
    kwargs for RBAC Resources CRUD operation

    Args:
        endpoint (str): HTTPRequest URI Path(REST endpoint)
        url_name (str): Name of resolved URI(Endpoint) in urlconf
        path_kwargs (dict): HTTPRequest Path kwargs

    Returns:
        tuple: tuple of resource_class, resource_serializer,
            project_info, pk_value
    """
    resource_info = {}

    project_info, pk_value = get_project_info_and_pk_value(url_name,
                                                           **path_kwargs)
    resource_info.update({
        'project_info': project_info,
        'pk_value': pk_value,
    })

    if fnmatch(url_name, 'add_remove_*'):
        combined_resource, resource_class, resource_serializer = \
            get_resource_info_for_add_remove(endpoint)
        resource_info.update({
            'combined_resource': combined_resource,
            'resource_class': resource_class,
            'resource_serializer': resource_serializer,
        })
    else:
        resource_class, resource_serializer = \
            get_resource_info_for_crud(url_name)
        resource_info.update({
            'resource_class': resource_class,
            'resource_serializer': resource_serializer,
        })

    return resource_info


def get_project_info_and_pk_value(url_name, **path_kwargs):
    """Prepare the RBAC Project Info(id and name) and resource Primary
    Key(pk) value from URI lookup value

    Args:
        url_name (str): Name of resolved URI(Endpoint) in urlconf
        path_kwargs (dict): HTTPRequest Path kwargs

    Returns:
        tuple: project_info and pk_value
    """
    pk_value = None
    project_info = {}
    if url_name != 'projects_list':
        project_name = path_kwargs['project_name']
        project_id = get_rbac_project_id_by_name(project_name)
        project_info = {
            'id': project_id,
            'name': project_name
        }
        if url_name == 'projects_detail':
            # For lookup, use RBACProject 'id' instead of 'name'
            pk_value = project_id
        else:
            try:
                pk_value = path_kwargs['pk']
            except KeyError:
                pass

    return project_info, pk_value


def get_resource_info_for_crud(url_name):
    """Get the RBAC Resource and Project information from URI and path
    kwargs for RBAC Resources CRUD operation

    Args:
        url_name (str): Name of resolved URI(Endpoint) in urlconf

    Returns:
        tuple: tuple of RBAC project id, project name, project
            serializer and a combined primary/secondary record
    """
    resource_name = DELIMITER.join(url_name.split(DELIMITER)[:-1])

    if url_name in ('projects_list', 'projects_detail'):
        # For RBACProject resource
        resource_class, resource_serializer = RESOURCES['projects'][1:]
    else:  # Rest of RBAC Resources
        resource_class, resource_serializer = RESOURCES[resource_name][1:]

    return resource_class, resource_serializer


def get_resource_info_for_add_remove(endpoint):
    """Get the RBAC resource information from URI for 'add' and 'remove'
        actions

    Args:
        endpoint (str): HTTPRequest URI Path(REST endpoint)

    Returns:
        tuple: tuple of RBAC project id, project name, project
            serializer and a combined primary/secondary record
    """
    # Sample URI:
    #   /v1/<namespace>/auth/project/ems/primary_res/pk1/secondary_res/pk2/

    primary_resource, primary_resource_pk_value, secondary_resource, \
        secondary_resource_pk_value = (
            endpoint.decode('unicode-escape').encode('utf8').rsplit('/')[6:10])

    combined_resource_name = DELIMITER.join((primary_resource,
                                             secondary_resource))

    resource_class, resource_serializer, primary_resource_pk, \
        secondary_resource_pk = (
            RESOURCES_FOR_ADD_REMOVE[combined_resource_name][1:])

    # Combine Primary and Secondary Resource
    combined_record = {
        DELIMITER.join((primary_resource, primary_resource_pk)):
            primary_resource_pk_value,
        DELIMITER.join((secondary_resource, secondary_resource_pk)):
            secondary_resource_pk_value
    }

    return combined_record, resource_class, resource_serializer


def check_request_from_localhost(client_ip):
    """Check if the HTTP request is from localhost.

    Args:
        client_ip(str): Address of Local Host

    Raises:
        PermissionDenied: If HTTP request is not coming from localhost
    """
    # Find the info of loopback('lo') device(interface)
    interface = netifaces.ifaddresses('lo').get(netifaces.AF_INET)
    if interface is None:
        raise PermissionDenied(detail='HTTP Request is not from a localhost')

    for i in interface:
        if i['addr'] == client_ip:
            return

    raise PermissionDenied(detail='HTTP Request is not from a localhost')


def get_client_ip(request):
    """Get Client IP Address

    Args:
        request (HTTPRequest):

    Returns:
        Client Address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
