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
from datetime import datetime, timedelta

from django.utils.crypto import get_random_string
from rest_framework import serializers
from auth.api.serializers.resource import ConsulSerializer, Resource
from auth.api.serializers.serializer_user import validate_credential_by_username
from auth.api.serializers.utils_serializers import (
    CustomUUIDField, generate_uuid
)

LOG = logging.getLogger(__name__)

AUTH_TOKEN_EXPIRY = 10  # in minutes


def generate_expiry_time():
    """Generate expiry time for Auth Token

    Returns:
        str: datetime in IS0 8601 string format
    """
    date_time = datetime.now() + timedelta(minutes=AUTH_TOKEN_EXPIRY)

    # For storing in backend, format datetime object to ISO 8601 string format
    return datetime.strftime(date_time, "%Y-%m-%dT%H:%M:%S")


def _generate_auth_token():
    """Generate Authorization Token

    Returns:
        str: Auth Token
    """
    return get_random_string(length=32)


class RBACAuthToken(Resource):
    """Represents an RBACAuthToken object"""
    resource_name = 'RBACAuthToken'
    primary_key = 'id'
    secondary_keys = ('auth_token','users_id')


class RBACAuthTokenSerializer(ConsulSerializer):
    """Serializer for RBACAuthToken"""
    consul_model = RBACAuthToken

    id = CustomUUIDField(default=generate_uuid)

    auth_token = serializers.CharField(default=_generate_auth_token)

    users_id = CustomUUIDField(read_only=True)

    username = serializers.CharField(write_only=True)

    password = serializers.CharField(min_length=5, write_only=True)

    expiry_time = serializers.DateTimeField(default=generate_expiry_time)

    def validate(self, attrs):
        user_id = validate_credential_by_username(self.context['project'],
                                                  attrs['username'],
                                                  attrs['password'])

        # Remove unrequired keys from the final resource
        pop_keys = ['username', 'password']
        new_attrs = {key: attrs[key] for key in attrs if key not in pop_keys}

        new_attrs['users_id'] = user_id
        return new_attrs
