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

# Resource Name to Consul Relation/Table Name Mapping
RESOURCE_TO_RELATION_MAP = {
    'Resource': 'resource',

    # RBAC Resources
    'RBACGroup': 'groups',
    'RBACGroupUser': 'groups_users',
    'RBACGroupCertificateUser': 'groups_certificate_users',
    'RBACProject': 'projects',
    'RBACRole': 'roles',
    'RBACRoleGroup': 'roles_groups',
    'RBACRoleRule': 'roles_rules',
    'RBACRule': 'rules',
    'RBACUser': 'users',
    'RBACAuthToken': 'auth_tokens',
    'RBACCertificateUser': 'certificate_users',
    'LDAPConfig': 'ldap_config',
}

# Consul Delimiter(Separator)
CONSUL_SEP = '/'
