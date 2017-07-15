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

from django.utils.translation import ugettext as _
from rest_framework import serializers

from auth.api.serializers.serializer_group import RBACGroup
from auth.api.serializers.serializer_rule import RULE_PERMISSIONS
from auth.api.serializers.serializer_user import RBACCertificateUser, RBACUser


class ResourcePermission(object):
    """Permissions on a resource endpoint for a RBACUser or
    RBACCertificateUser.
    """

    @staticmethod
    def get_permissions(user_info, resource_endpoint, project_info):
        """Find permissions associated with a resource endpoint for a
        particular user.

        Args:
            user_info (dict): User id and type(RBACUser or
                RBACCertificateUser)
            resource_endpoint(str): Resource Endpoint
            project_info (dict): RBACProject id and name

        Returns:
            list: All the permissions for the user on the endpoint.
                Empty list([]) if there is no permission.
        """

        if resource_endpoint is None:
            raise serializers.ValidationError(
                    _("HTTP X-Authorization-Endpoint Header not set"))

        # Allow all permissions for Admin user
        if user_info['is_admin']:
            return RULE_PERMISSIONS

        # Find user info.
        if user_info['is_cert']:
            # RBACCertificateUser
            user = RBACCertificateUser.get(**{
                'id': user_info['id'],
                'project': project_info
                })
        else:
            # RBACUser
            user = RBACUser.get(**{
                'id': user_info['id'],
                'project': project_info
                })

        # Collect RBACGroup(s) belonging to the user
        group_ids = [group['id'] for group in user.groups]

        permissions = set()

        for group_id in group_ids:
            group = RBACGroup.get(**{
                'id': group_id,
                'project': project_info
               })

            # For each RBACGroup, check all the RBACRole(s)
            for role in group.roles:
                for rule in role['rules']:
                    if fnmatch(resource_endpoint, rule['resource_endpoint']):
                        permissions.update(set(rule['permissions']))
                        # Don't check further for lower order rules
                        break

        return list(permissions)
