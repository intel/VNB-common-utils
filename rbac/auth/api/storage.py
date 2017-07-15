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
import os
from yapsy.PluginManager import PluginManager

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('yapsy').setLevel(logging.DEBUG)

# Yapsy Framework to load a plugin

# Load the plugins from the plugin directory.
manager = PluginManager()

# Location of consul plugin
here = os.path.dirname(__file__)
relative_path_of_plugin = os.path.join(here, 'storage_plugin')

manager.setPluginPlaces([relative_path_of_plugin])
manager.collectPlugins()

# Loop around the plugins and return the first plugin object.
for storage_plugin in manager.getAllPlugins():
    plugin = storage_plugin.plugin_object
