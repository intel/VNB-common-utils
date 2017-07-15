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
    CustomUUIDField, generate_uuid
)


class LDAPConfig(Resource):
    """Represents an LDAP Configuration object"""
    resource_name = 'LDAPConfig'
    primary_key = 'id'
    secondary_keys = ()


class LDAPConfigSerializer(ConsulSerializer):
    """Serializer for LDAPConfig"""
    consul_model = LDAPConfig

    id = CustomUUIDField(default=generate_uuid)

    ldap_uri = serializers.CharField()

    description = serializers.CharField(required=False)

    ldap_version = serializers.ChoiceField(choices=('v2', 'v3',), default='v3')

    relative_distinguished_name = serializers.CharField()
