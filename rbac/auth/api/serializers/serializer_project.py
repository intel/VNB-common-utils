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

from rest_framework import serializers

from auth.api.serializers.resource import Resource, ConsulSerializer
from auth.api.serializers.utils_serializers import (
    check_project_name_not_exists, CustomUUIDField, generate_uuid
)


class RBACProject(Resource):
    """Represents an RBACProject object

    A RBACProject provides a namespace other RBAC resources. All the other
    resources are managed under a certain RBACProject.
    """
    resource_name = 'RBACProject'
    primary_key = 'id'
    secondary_keys = ('name',)


class RBACProjectSerializer(ConsulSerializer):
    """Serializer for RBACProject"""
    consul_model = RBACProject

    id = CustomUUIDField(default=generate_uuid)

    name = serializers.CharField(validators=[check_project_name_not_exists])

    description = serializers.CharField(required=False)
