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
from rest_framework import status

"""Custom Exceptions for RBAC"""


class RBACException(Exception):
    default_detail = _('RBAC Exception')
    default_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    def __init__(self, detail=None, code=None, arg=None, *args):
        if detail is None:
            self.detail = self.default_detail
        if code is None:
            self.code = self.default_code


class ResourceNotFound(RBACException):
    """RBAC Resource not found"""
    default_detail = _('Resource not found')
    default_code = status.HTTP_404_NOT_FOUND

    def __init___(self, detail=None, arg=None):
        super(ResourceNotFound, self).__init__(self, 'Resource with id {0} not '
                                                     'found'.format(arg))


class PKUpdateNotPermitted(RBACException):
    """RBAC Resource Primary Key update not permitted"""
    default_detail = _('Primary Key field update not permitted')
    default_code = status.HTTP_400_BAD_REQUEST
