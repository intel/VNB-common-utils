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

from django.utils.translation import ugettext as _
from rest_framework import permissions

NON_ADMIN_NON_RESTRICTED_RESOURCE = (
    'RBACUser',
    'RBACAuthToken',
)


class ResourceAccessPermission(permissions.BasePermission):
    """Restrict access of certain resource"""

    def has_permission(self, request, view):
        message = _("Permission denied to access this resource")

        if view.kwargs['resource_class'].resource_name in \
                NON_ADMIN_NON_RESTRICTED_RESOURCE:
            return True
        else:
            return request.user['is_admin'] == True

    def has_object_permission(self, request, view, obj):
        message = _("Permission denied to access this resource")

        if view.kwargs['resource_class'].resource_name == 'RBACUser':
            return request.kwargs['pk'] == obj.id


