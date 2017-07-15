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

from auth.api.serializers.serializer_authentication import (
    RBACAuthTokenSerializer, RBACAuthToken
)
from auth.api.serializers.serializer_group import(
    RBACGroup, RBACGroupSerializer, RBACGroupUser, RBACGroupUserSerializer,
    RBACGroupCertificateUser, RBACGroupCertificateUserSerializer
)
from auth.api.serializers.serializer_ldap_config import (
    LDAPConfig, LDAPConfigSerializer
)
from auth.api.serializers.serializer_project import (
    RBACProject, RBACProjectSerializer
)
from auth.api.serializers.serializer_role import (
    RBACRole, RBACRoleSerializer, RBACRoleGroup, RBACRoleGroupSerializer,
    RBACRoleRuleSerializer
)
from auth.api.serializers.serializer_rule import RBACRule
from auth.api.serializers.serializer_user import (
    RBACCertificateUser, RBACCertificateUserSerializer,
    RBACChangeUserPasswordSerializer, RBACUser, RBACUserSerializer
)

"""
    Mapping from URI names to project (Class and Serializer)

    Note: HTTP resource is the key for the below dictionary.
"""

RESOURCES = {
    'groups': (
        RBACGroup.resource_name,
        RBACGroup,
        RBACGroupSerializer,
    ),
    'projects': (
        RBACProject.resource_name,
        RBACProject,
        RBACProjectSerializer,
    ),
    'roles': (
        RBACRole.resource_name,
        RBACRole,
        RBACRoleSerializer,
    ),
    'users': (
        RBACUser.resource_name,
        RBACUser,
        RBACUserSerializer,
    ),
    'changepassword': (
        RBACUser.resource_name,
        RBACUser,
        RBACChangeUserPasswordSerializer,
    ),
    'certificate_users': (
        RBACCertificateUser.resource_name,
        RBACCertificateUser,
        RBACCertificateUserSerializer,
    ),
    'tokens': (
        RBACAuthToken.resource_name,
        RBACAuthToken,
        RBACAuthTokenSerializer,
    ),
    'permissions': (
        RBACAuthToken.resource_name,
        RBACAuthToken,
        RBACAuthTokenSerializer,
    ),
    'ldap_config': (
        LDAPConfig.resource_name,
        LDAPConfig,
        LDAPConfigSerializer,
    ),
}

"""
    Note: Only required for ADD/REMOVE action
    Mapping from URI names to combined resources
    (Class, Serializer and Primary Key of individual project)

    Note: Primary and Secondary HTTP resources are joined by '_' which
          forms the key for the below dictionary.
"""

RESOURCES_FOR_ADD_REMOVE = {
    'groups_users': (
        RBACGroupUser.resource_name,
        RBACGroupUser,
        RBACGroupUserSerializer,
        RBACGroup.primary_key,
        RBACUser.primary_key,
    ),
    'groups_certificate_users': (
        RBACGroupCertificateUser.resource_name,
        RBACGroupCertificateUser,
        RBACGroupCertificateUserSerializer,
        RBACGroup.primary_key,
        RBACUser.primary_key,
    ),
    'roles_groups': (
        RBACRoleGroup.resource_name,
        RBACRoleGroup,
        RBACRoleGroupSerializer,
        RBACRole.primary_key,
        RBACGroup.primary_key,
    ),
    'roles_rules': (
        RBACRole.resource_name,
        RBACRole,
        RBACRoleRuleSerializer,
        RBACRole.primary_key,
        RBACRule.primary_key,
    ),
}
