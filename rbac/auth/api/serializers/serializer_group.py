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
from auth.api.serializers.serializer_project import RBACProjectSerializer
from auth.api.serializers.serializer_user import (
    RBACUserSerializer, RBACCertificateUserSerializer
)
from auth.api.serializers.utils_serializers import (
    check_certificate_user_exists, check_group_exists, check_user_exists,
    CustomUUIDField, generate_uuid
)


class RBACGroup(Resource):
    """Represents an RBACGroup object"""
    resource_name = 'RBACGroup'
    primary_key = 'id'
    secondary_keys = ('name',)
    many_references = (
        'RBACGroupUser',
        'RBACGroupCertificateUser',
        'RBACRoleGroup',
    )


class RBACGroupSerializer(ConsulSerializer):
    """Serializer for RBACGroup"""
    consul_model = RBACGroup

    id = CustomUUIDField(default=generate_uuid)

    name = serializers.CharField()

    description = serializers.CharField(required=False)

    project = RBACProjectSerializer(read_only=True)

    users = RBACUserSerializer(many=True, read_only=True)

    certificate_users = RBACCertificateUserSerializer(many=True, read_only=True)


class RBACGroupUser(Resource):
    """Represents an RBACGroupUser object"""
    resource_name = 'RBACGroupUser'
    primary_key = 'id'
    many_to_many_reference = ('RBACGroup', 'RBACUser',)


class RBACGroupUserSerializer(ConsulSerializer):
    """Serializer for RBACGroupUserSerializer"""
    consul_model = RBACGroupUser

    id = CustomUUIDField(default=generate_uuid)

    groups_id = CustomUUIDField()

    users_id = CustomUUIDField()

    def validate_groups_id(self, group_id):
        check_group_exists(self.context['project']['id'], group_id)
        return group_id

    def validate_users_id(self, user_id):
        check_user_exists(self.context['project']['id'], user_id)
        return user_id


class RBACGroupCertificateUser(Resource):
    """Represents an RBACGroupCertificateUser object"""
    resource_name = 'RBACGroupCertificateUser'
    primary_key = 'id'
    many_to_many_reference = ('RBACGroup', 'RBACCertificateUser',)


class RBACGroupCertificateUserSerializer(ConsulSerializer):
    """Serializer for RBACGroupCertificateUserSerializer"""
    consul_model = RBACGroupCertificateUser

    id = CustomUUIDField(default=generate_uuid)

    groups_id = CustomUUIDField()

    certificate_users_id = CustomUUIDField()

    def validate_groups_id(self, group_id):
        check_group_exists(self.context['project']['id'], group_id)
        return group_id

    def validate_certificate_users_id(self, certificate_user_id):
        check_certificate_user_exists(self.context['project']['id'],
                                      certificate_user_id)
        return certificate_user_id

