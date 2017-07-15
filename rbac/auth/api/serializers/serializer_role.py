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
from rest_framework import serializers

from auth.api.serializers.resource import Resource, ConsulSerializer
from auth.api.serializers.serializer_group import RBACGroupSerializer
from auth.api.serializers.serializer_rule import RBACRuleSerializer
from auth.api.serializers.utils_serializers import (
    check_group_exists, check_role_exists, CustomUUIDField, generate_uuid
)


class RBACRole(Resource):
    """Represents an RBACRole object"""
    resource_name = 'RBACRole'
    primary_key = 'id'
    secondary_keys = ('name',)
    many_references = ('RBACRoleGroup',)


class RBACRoleSerializer(ConsulSerializer):
    """Serializer for RBACRole"""
    consul_model = RBACRole

    id = CustomUUIDField(default=generate_uuid)

    name = serializers.CharField()

    description = serializers.CharField(required=False)

    groups = RBACGroupSerializer(many=True, read_only=True)

    rules = serializers.ListField(child=RBACRuleSerializer(),
                                  default=[],
                                  required=False)

    @staticmethod
    def validate_rules(rules):
        order_set = set()
        for rule in rules:
            order = rule.get('order', None)

            # Check whether the rule has an assigned order
            if order is None:
                raise serializers.ValidationError(
                    {'detail': _("Rule order for %s cannot be empty") %
                        rule['resource_endpoint']})

            # Check whether the rule has a valid order
            if not(order <= len(rules)):
                raise serializers.ValidationError(
                    {'detail': _("Invalid rule order %s for %s. The order "
                                 "cannot be greater than total number of "
                                 "rules") % (order, rule['resource_endpoint'])})

            # Check all the rules' order are distinct
            if order in order_set:
                raise serializers.ValidationError(
                    {'detail': _("Multiple rules with the order %s. All the "
                                 "rules' order must be distinct." % order)})
            else:
                order_set.add(order)

        sorted(rules, key=lambda rule: rule['order'])

        return rules


class RBACRoleGroup(Resource):
    """Represents an RBACGroupRole object"""
    resource_name = 'RBACRoleGroup'
    primary_key = 'id'
    many_to_many_reference = ('RBACRole', 'RBACGroup',)


class RBACRoleGroupSerializer(ConsulSerializer):
    """Serializer for RBACGroupRole"""
    consul_model = RBACRoleGroup

    id = CustomUUIDField(default=generate_uuid)

    roles_id = CustomUUIDField()

    groups_id = CustomUUIDField()

    def validate_roles_id(self, roles_id):
        check_role_exists(self.context['project']['id'], roles_id)
        return roles_id

    def validate_groups_id(self, groups_id):
        check_group_exists(self.context['project']['id'], groups_id)
        return groups_id


class RBACRoleRuleSerializer(RBACRoleSerializer):
    """Serializer for RBACGroupRole"""
    consul_model = RBACRole
