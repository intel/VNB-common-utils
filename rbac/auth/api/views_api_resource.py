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

from django.utils.translation import ugettext as _
from rest_framework.generics import (
    CreateAPIView, DestroyAPIView, ListCreateAPIView, RetrieveAPIView,
    RetrieveUpdateDestroyAPIView, UpdateAPIView,
)
from rest_framework.exceptions import MethodNotAllowed, NotFound
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_200_OK, HTTP_204_NO_CONTENT, HTTP_401_UNAUTHORIZED
)
from rest_framework.views import APIView

from auth.api.authentication import TokenCertificateAuthentication
from auth.api.permission import ResourceAccessPermission
from auth.api.project_registration import RBACProjectRegistration
from auth.api.resource_permission import ResourcePermission
from auth.api.serializers.serializer_authentication import RBACAuthToken
from auth.api.serializers.serializer_rule import (
    process_add_rule, process_change_rule_order, process_delete_rule
)
from auth.api.views_utils import (
    check_request_from_localhost, get_client_ip, get_resource_info
)

LOG = logging.getLogger(__name__)


class GenericCommonResourceMixin(object):
    """This Mixin provides common methods required for all the CRUD
    operations. It initializes the HTTP request, finds the serializer
    class for the HTTP resource and fills the serializer context. It
    also logs the HTTP request in before finalizing the response.
    """

    authentication_classes = (TokenCertificateAuthentication,)
    permission_classes = (ResourceAccessPermission,)

    def initial(self, request, *args, **kwargs):

        check_request_from_localhost(get_client_ip(request))

        resource_info = get_resource_info(request.get_full_path(),
                                          request.resolver_match.url_name,
                                          **kwargs)
        for key in resource_info.keys():
            self.kwargs[key] = resource_info[key]

        super(GenericCommonResourceMixin, self).initial(request,
                                                        *args,
                                                        **kwargs)

    def get_serializer_class(self):
        return self.kwargs['resource_serializer']

    def get_serializer_context(self):
        return {
            self.kwargs['resource_class'].primary_key: self.kwargs['pk_value'],
            'project': self.kwargs['project_info'],
            'user': self.request.user
        }

    def get_resource_class_and_search_info(self):
        rbac_resource = self.kwargs['resource_class']

        search_info = {
            rbac_resource.primary_key: self.kwargs['pk_value'],
            'project': self.kwargs['project_info']
        }

        return rbac_resource, search_info

    def finalize_response(self, request, response, *args, **kwargs):
        LOG.info('"%s %s %s" %s',
                 request.method,
                 request.get_full_path(),
                 request.META.get('SERVER_PROTOCOL'),
                 response.status_code)

        # This prevents the 'Authentication Required' popup in some browsers
        if response.status_code == HTTP_401_UNAUTHORIZED:
            response['WWW-Authenticate'] = 'TokenBased'

        return super(GenericCommonResourceMixin, self).finalize_response(
                    request,
                    response,
                    *args,
                    **kwargs)


"""View to handle CRUD operation for RBAC Resources"""


class GenericListCreateResourceView(GenericCommonResourceMixin,
                                    ListCreateAPIView):
    """Create(POST)/List(GET) for RBAC HTTP resources: Project, User
    Role and Rule"""

    def get_queryset(self):
        rbac_resource, search_info = self.get_resource_class_and_search_info()

        return rbac_resource.all(**search_info)

    # def filter_queryset(self, queryset):
    #     if self.kwargs['resource_class'].resource_name != 'RBACUser':
    #         return queryset
    #     else:
    #         new_queryset = list()
    #         for user in queryset:
    #             if user['id'] == self.request.user['id']:
    #                 new_queryset = list()
    #                 new_queryset.append(user)
    #         return new_queryset


class GenericRetrieveUpdateDestroyResourceView(GenericCommonResourceMixin,
                                               RetrieveUpdateDestroyAPIView):
    """Show(GET)/Update(PATCH)/Delete(DELETE) for RBAC HTTP resources:
    Project, User, Role and Rule"""

    def get_object(self):
        rbac_resource, search_info = self.get_resource_class_and_search_info()

        resource_object = rbac_resource.get(**search_info)

        if resource_object is None:
            raise NotFound(detail=_("%s with %s %s not found") %
                           (rbac_resource.resource_name,
                            rbac_resource.primary_key,
                            self.kwargs['pk_value']))

        # Add RBACProject info to Resource except for RBACProject
        project_info = self.kwargs['project_info']
        if project_info is not None:
            resource_object.project = self.kwargs['project_info']

        return resource_object

    def put(self, request, *args, **kwargs):
        # HTTP PUT method is not allowed on RBAC Resources
        raise MethodNotAllowed(request.method)


"""View to handle generate/revoke authentication tokens(Login/Logout)"""


class AuthTokenResourceView(GenericCommonResourceMixin,
                            CreateAPIView,
                            DestroyAPIView):

    def post(self, request, *args, **kwargs):
        record = super(AuthTokenResourceView,self).post(request,
                                                        *args,
                                                        **kwargs)

        # Delete the existing Auth Token before returning a new token
        project_info = request.parser_context['kwargs']['project_info']
        search_info = {
            'users_id': record.data['users_id'],
            'project': project_info
        }
        tokens = RBACAuthToken.get(**search_info)

        for token in tokens:
            if token.id != record.data['id']:
                token.project = project_info
                token.delete()

        return Response(record.data, record.status_code)

    def delete(self, request, *args, **kwargs):
        if request.user is None:
            return Response(status=HTTP_204_NO_CONTENT)


"""View to handle checking of permissions"""


class CheckResourcePermissionView(GenericCommonResourceMixin,
                                  RetrieveAPIView):

    def get(self, request, *args, **kwargs):
        permissions = ResourcePermission().get_permissions(
                    request.user,
                    request.META.get('HTTP_X_AUTHORIZATION_ENDPOINT'),
                    kwargs['project_info'])
        return Response({'permissions': permissions})


"""View to handle assign/remove a secondary resource to a primary resource"""


class AddRemoveResourceView(GenericCommonResourceMixin,
                            UpdateAPIView,
                            DestroyAPIView):

    def put(self, request, *args, **kwargs):
        # Add a secondary RBAC Resource to primary RBAC Resource
        serializer = self.get_serializer(data=self.kwargs['combined_resource'])
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        # Remove a secondary RBAC Resource from primary RBAC Resource
        serializer = self.get_serializer(data=self.kwargs['combined_resource'])
        serializer.is_valid(raise_exception=True)
        serializer.custom_serializer_delete()
        return Response(status=HTTP_204_NO_CONTENT)


"""View to handle add/remove/change-order of rules for RBACRole"""


class AddRemoveChangeRuleView(GenericCommonResourceMixin,
                              UpdateAPIView,
                              DestroyAPIView):

    def get_object(self):
        rbac_resource, search_info = self.get_resource_class_and_search_info()

        search_info['id'] = self.kwargs['combined_resource']['roles_id']
        resource_object = rbac_resource.get(**search_info)

        if resource_object is None:
            raise NotFound(detail=_("%s with %s %s not found") %
                           (rbac_resource.resource_name,
                            rbac_resource.primary_key,
                            self.kwargs['pk_value']))

        resource_object.project = self.kwargs['project_info']

        return resource_object

    def put(self, request, *args, **kwargs):
        instance = process_add_rule(self.get_object(), request.data)
        serializer = self.get_serializer(data=instance)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(instance)

    def patch(self, request, *args, **kwargs):
        instance = process_change_rule_order(
                self.get_object(),
                self.kwargs['combined_resource']['rules_id'],
                self.kwargs['orders_no'])
        serializer = self.get_serializer(data=instance)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(instance)

    def delete(self, request, *args, **kwargs):
        instance = process_delete_rule(
                self.get_object(),
                self.kwargs['combined_resource']['rules_id'])
        serializer = self.get_serializer(data=instance)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(instance)


"""View to handle Registration of a Project"""


class ProjectRegistrationView(APIView):

    def post(self, request, *args, **kwargs):
        project_id = RBACProjectRegistration().register_project(request.data)
        return Response({'project_id': project_id})



