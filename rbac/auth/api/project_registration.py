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

from django.contrib.auth.hashers import make_password
from rest_framework import serializers

from auth.api.serializers.serializer_project import (
    RBACProject, RBACProjectSerializer
)
from auth.api.serializers.serializer_user import RBACUser
from auth.api.serializers.utils_serializers import (
    check_project_name_not_exists, generate_uuid
)


class RBACProjectRegistration(object):
    """Register Project/App with RBAC"""

    def register_project(self, project_data):
        return self._create_project(project_data)

    def _create_project(self, project_data):
        """Create a RBACProject with the provided name

        Args:
            project_data(dict): HTTP request data

        Returns:
            str: Registered RBACProject id
        """
        serializer = RBACProjectSerializer(data=project_data)

        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError:
            check_project_name_not_exists(project_data['name'])

        project = RBACProject(**serializer.validated_data)
        project.save()

        project_info = {
            'id': serializer.validated_data['id'],
            'name': serializer.validated_data['name']
        }
        self._create_admin_user(project_info)

        return project.id

    @staticmethod
    def _create_admin_user(project_info):
        """Create a default admin user for the registered project

        Args:
            project_info: Registered RBACProject info(id & name)
        """
        default_admin_user_detail = {
            'id': generate_uuid(),
            'username': 'admin',
            'password': make_password('admin'),
            'is_admin': True,
            'auth_by_ldap': False
        }
        user = RBACUser(**default_admin_user_detail)
        user.project = project_info
        user.save()
