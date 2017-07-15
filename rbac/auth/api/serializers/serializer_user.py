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

from django.contrib.auth.hashers import make_password, check_password
from django.utils.translation import ugettext as _
from rest_framework import serializers

from auth.api.serializers.resource import Resource, ConsulSerializer
from auth.api.serializers.serializer_ldap_config import LDAPConfig
from auth.api.serializers.serializer_project import RBACProjectSerializer
from auth.api.serializers.utils_serializers import (
    CustomUUIDField, check_username_exists, generate_uuid
)
import ldap

LOG = logging.getLogger(__name__)


class RBACUser(Resource):
    """Represents an RBACUser object"""
    resource_name = 'RBACUser'
    primary_key = 'id'
    secondary_keys = ('username',)
    many_references = ('RBACGroupUser',)


class RBACUserSerializer(ConsulSerializer):
    """Serializer for RBACUser"""
    consul_model = RBACUser

    id = CustomUUIDField(default=generate_uuid)

    email = serializers.EmailField(required=False)

    description = serializers.CharField(required=False)

    username = serializers.CharField()

    password = serializers.CharField(min_length=5, write_only=True)

    is_admin = serializers.BooleanField(default=False)

    auth_by_ldap = serializers.BooleanField(default=False)

    ldap_config_id = CustomUUIDField(required=False)

    project = RBACProjectSerializer(read_only=True)

    def validate_username(self, username):
        check_username_exists(self.context['project']['id'], username)
        return username

    def validate_is_admin(self, is_admin):
        if not self.context['user']['is_admin']:
            raise serializers.ValidationError(
                    {'detail': _("Non-Admin user cannot set 'is_admin' field")})
        return is_admin

    @staticmethod
    def validate_password(password):
        return make_password(password)

    def validate(self, attrs):
        # Make sure valid values have been provided for both 'auth_by_ldap' and
        # 'ldap_config_id'
        if attrs.get('auth_by_ldap', False):
            if attrs.get('ldap_config_id', None) is None:
                raise serializers.ValidationError(
                    {'detail': _("'ldap_config_id' value should be provided "
                                 "with 'auth_by_ldap' value")})

        if attrs.get('ldap_config_id', None) is not None:
            if not attrs.get('auth_by_ldap', False):
                raise serializers.ValidationError(
                    {'detail': _("'auth_by_ldap' value should be provided with "
                                 "'ldap_config_id' value")})

        return attrs


class RBACChangeUserPasswordSerializer(ConsulSerializer):
    consul_model = RBACUser

    original_password = serializers.CharField(min_length=5, write_only=True)

    password = serializers.CharField(min_length=5, write_only=True)

    def validate(self, attrs):
        validate_credential_by_id(self.context['project'],
                                  self.context['id'],
                                  attrs['original_password'])

        return {'password': make_password(attrs['password'])}


class RBACCertificateUser(Resource):
    """Represents an RBACCertificateUser object"""
    resource_name = 'RBACCertificateUser'
    primary_key = 'id'
    secondary_keys = ('subject_pattern',)


class RBACCertificateUserSerializer(ConsulSerializer):
    """Serializer for RBACCertificateUser"""
    consul_model = RBACCertificateUser

    id = CustomUUIDField(default=generate_uuid)

    subject_pattern = serializers.CharField()

    description = serializers.CharField(required=False)

    project = RBACProjectSerializer(read_only=True)


def validate_credential_by_username(project, username, password):
    """Check whether RBACUser username & password is a valid credential

    Args:
        project (dict): RBACProject info(id and name)
        username (str): RBACUser username
        password (str): RBACUser password

    Raises:
        serializers.ValidationError: When credential is invalid

    Returns:
        str: RBACUser id if credential is valid
    """
    LOG.info(_("Validate credential for RBACUser with username %s") %
             username)

    search_info = {
        'username': username,
        'project': project
    }

    records = RBACUser.get(**search_info)

    if not records:
        raise serializers.ValidationError(
            {'detail': _("RBACUser with username %s does not exist." %
                         username)})

    # There should be just one record with a particular username
    assert len(records) == 1

    # Get the first and only record from the list
    credential = records[0]

    if credential.auth_by_ldap:
        return _authenticate_credential_by_ldap(credential,
                                                project,
                                                username,
                                                password,
                                                credential.ldap_config_id)
    else:
        return _authenticate_credential_by_rbac(credential, username, password)


def _authenticate_credential_by_rbac(credential, username, password):
    """Authenticate credential by with RBAC data store values

    Args:
        credential (RBACUser): username & password of user
        username (str): RBACUser username
        password (str): RBACUser password

    Returns:
        str: RBACUser id if credential is valid
    """
    if not (credential.username == username and
            (check_password(password, credential.password))):
        raise serializers.ValidationError(
            {'detail': _("Invalid username/password for RBACUser with "
                         "username %s" % username)})

    LOG.info(_("Credential validation successful for RBACUser with "
               "username %s") % username)

    return credential.id


def _authenticate_credential_by_ldap(credential, project, username, password,
                                     ldap_config_id):
    """Authenticate credential by RBAC

    Args:
        credential(RBACUser): username & password of user
        project (dict): RBACProject info(id and name)
        username (str): RBACUser username
        password (str): RBACUser password
        ldap_config_id (str): id of LDAP config(LDAP URI and scope subtree)

    Returns:
        str: RBACUser id if credential is valid
    """
    search_info = {
        'id': ldap_config_id,
        'project': project
    }

    ldap_config = LDAPConfig.get(**search_info)

    if ldap_config is None:
        return

    username = 'cn=' + username + ',' + ldap_config.relative_distinguished_name

    try:
        conn = ldap.open(ldap_config.ldap_uri)

        if ldap_config.ldap_version == 'v2':
            conn.version = ldap.VERSION2
        else:
            conn.version = ldap.VERSION3

        conn.simple_bind_s(username, password)
    except ldap.LDAPError:
        raise serializers.ValidationError({'detail': "LDAP Authentication "
                                                     "Error"})

    return credential.id


def validate_credential_by_id(project, user_id, password):
    """Check whether RBACUser id and password is a valid credential

    Args:
        project (dict): RBACProject info(id and name)
        user_id (str): RBACUser id
        password (str): RBACUser password

    Raises:
        serializers.ValidationError: When credential is invalid

    Returns:
        str: RBACUser id if credential is valid
    """
    LOG.info(_("Validate credential for RBACUser with id %s") % user_id)

    search_info = {
        'id': user_id,
        'project': project
    }

    credential = RBACUser.get(**search_info)

    if credential is None:
        raise serializers.ValidationError(
            {'detail': _("RBACUser with id %s does not exist." % user_id)})

    if not check_password(password, credential.password):
        raise serializers.ValidationError(
            {'detail': _("Invalid password for RBACUser with id %s" % user_id)})

    LOG.info(_("Credential validation successful for RBACUser with id %s") %
             user_id)

    return credential.id
