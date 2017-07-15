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

from datetime import datetime
from fnmatch import fnmatch

from django.utils.translation import ugettext as _
from rest_framework import serializers
from rest_framework.authentication import BasicAuthentication
from rest_framework.exceptions import AuthenticationFailed

from auth.api.serializers.serializer_authentication import (
    generate_expiry_time, RBACAuthToken
)
from auth.api.serializers.serializer_user import RBACCertificateUser, RBACUser


class TokenCertificateAuthentication(BasicAuthentication):
    """Token and Certificate based Authentication"""

    def authenticate(self, request, *args, **kwargs):
        # No Authentication for Token Creation(Login) request
        if request.resolver_match.url_name == 'tokens_details' and \
                request.method == 'POST':
            return None, None

        auth_token = request.META.get('HTTP_X_AUTH_TOKEN', '')

        cert_subject_dn = request.META.get('HTTP_X_SSL_CLIENT_S_DN', '')

        if not auth_token and not cert_subject_dn:
            raise serializers.ValidationError({'detail': _(
                "HTTP Header 'X-Auth-Token' or 'X-SSL-Client-S-DN' "
                "is not set")})

        project_info = request.parser_context['kwargs']['project_info']

        # Prepare info. for RBACCertificateUser
        if auth_token is None:
            cert_users = RBACCertificateUser.all(**project_info)

            for cert_subject_rdn in self.get_subject_rdn(cert_subject_dn):
                for cert_user in cert_users:
                    if fnmatch(cert_subject_rdn, cert_user.subject_pattern):
                        user_info = {
                            'id': cert_user.id,
                            'is_cert': True,
                            'is_admin': False  # RBACCertificateUser can't be
                                               # admin
                        }
                        return user_info, None

            raise AuthenticationFailed(_("Invalid CertificateUser's "
                                         "Subject/Alt. Name"))

        # Prepare info. for RBACUser
        auth_token_value = auth_token.split()[1]

        search_info = {
            'auth_token': auth_token_value,
            'project': project_info
        }
        records = RBACAuthToken.get(**search_info)

        if not records:
            raise AuthenticationFailed(_("Invalid Authentication Token"))

        # There should be just one record with a particular username
        assert len(records) == 1

        auth_token = records[0]
        auth_token.project = project_info

        # Format string stored in backend to compare with datetime object
        date_time = datetime.strptime(auth_token.expiry_time,
                                      "%Y-%m-%dT%H:%M:%S")

        if date_time < datetime.now():
            auth_token.delete()
            raise AuthenticationFailed(_("Authentication Token has expired"))
        elif request.resolver_match.url_name == 'tokens_details' and \
                request.method == 'DELETE':
            # Delete the RBACAuthToken for logout request
            auth_token.delete()
            return None, None
        else:
            # Update(Refresh) the expiry time and store back the RBACAuthToken
            auth_token.expiry_time = generate_expiry_time()
            auth_token.save()

            # Find if RBACUser is admin
            search_info = {
                'id': auth_token.users_id,
                'project': project_info
            }
            user = RBACUser.get(**search_info)

            user_info = {
                'id': auth_token.users_id,
                'is_cert': False,
                'is_admin': user.is_admin
            }
            return user_info, None

    @staticmethod
    def get_subject_rdn(cert_subject_dn):
        """Get the certificate subject relative distinguished names(RDN)

        Args:
            cert_subject_dn (str): Certificate Subject Distinguished
                Name

        Returns:
            RDNs of certificate subject
        """
        # In a Certificate subject, each RDN is separated by ','
        cert_subject_dn_parts = ','.split(cert_subject_dn)
        rdns = []
        for part in cert_subject_dn_parts:
            # Each RDN is a tuples separated by '='. We are only interested in
            # the values of RDN
            rdns.append('='.split(part)[1])
        return rdns
