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

import consul_config as cfg


class CustomEncoder(json.JSONEncoder):
    """Extend JSONEncoder to handle set type. Convert set to list"""
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


def str_to_dict(value):
    """Converts a string expression to dict

    Args:
        value (str) : value

    Returns:
        dict
    """
    return json.loads(value)


def consul_key_join(*args):
    """Prepare consul key(partial or complete) with consul
    delimiter('/')

    Args:
        args (tuple): consul key elements

    Returns:
        unicode: consul key with consul delimiter
    """
    return cfg.CONSUL_APP + '/' + '/'.join(args)
