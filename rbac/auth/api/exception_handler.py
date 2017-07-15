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
import json
import logging

from django.utils.translation import ugettext as _
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import exception_handler

from auth.api.exceptions import RBACException

LOG = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    level = LOG.info

    if isinstance(exc, RBACException):
        return Response(data={'detail': exc.detail},
                        status=exc.code,
                        content_type='application/json')

    # Non standard DRF exceptions result in HTTP response as None
    if response is None:
        level = LOG.exception
        response = Response(data={'detail': _('A server error occurred')},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            content_type='application/json')
    else:
        if response.status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
            level = LOG.error
            response.data = _('A server error occurred')
        elif response.status_code >= status.HTTP_400_BAD_REQUEST:
            level = LOG.warning

    request = context['request']
    response.data['status_code'] = response.status_code

    level('"%s %s %s" %s Detail:  %s',
          request.method,
          request.get_full_path(),
          request.META.get('SERVER_PROTOCOL'),
          response.status_code,
          json.dumps(response.data))

    return response
