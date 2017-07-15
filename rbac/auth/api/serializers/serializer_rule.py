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
from auth.api.serializers.utils_serializers import (
    CustomUUIDField, generate_uuid
)

# Possible Permissions for a rule
RULE_PERMISSIONS = (
    'VIEW',    # GET
    'ADD',     # POST
    'CHANGE',  # PATCH/PUT
    'DELETE',  # DELETE
)


class RBACRule(Resource):
    """Represents an RBACRule object

    A RBACRule exists as a part of RBACRole. A RBACRule represents the
    resource endpoint(or an endpoint wildcard pattern) and the related
    permissions on the endpoint. Every rule also a priority order. The
    priority order determines which rule will take precedence if more
    than one rules match the resource endpoint pattern during
    authorization.
    """
    resource_name = 'RBACRule'
    primary_key = 'id'
    secondary_keys = ('name',)


class RBACRuleSerializer(ConsulSerializer):
    """Serializer for RBACRule"""
    consul_model = RBACRule

    id = CustomUUIDField(default=generate_uuid)

    resource_endpoint = serializers.CharField()

    order = serializers.IntegerField(required=False)

    permissions = serializers.MultipleChoiceField(choices=RULE_PERMISSIONS)

    def validate(self, attrs):
        # Check the rule's order is not negative
        try:
            if attrs['order'] < 0:
                raise serializers.ValidationError(
                    {'detail': _("Invalid rule order %s for %s. The order "
                                 "must be a positive integer." % (
                                  attrs['order'], attrs['resource_endpoint']))})
        except KeyError:
            return attrs
        else:
            return attrs

#
# RBAC Rules Processing for add/delete/change-order operations
#


def process_add_rule(role, rule):
    """Add a rule to existing list of rules in a RBACRole

    Args:
        role (RBACRole): RBACRole instance
        rule (dict): New Rule to be added

    Returns:
        dict: Updated RBACRole role dict
    """
    # Validate the provided new rule fields
    serializer = RBACRuleSerializer(data=rule)
    serializer.is_valid(raise_exception=True)
    new_rule = serializer.validated_data
    try:
        rule_order = new_rule['order']
        role.rules.insert(new_rule['order'] - 1, new_rule)
        # Update the order of affected rules by new rule insertion
        for i, rule in enumerate(role.rules[rule_order:],
                                 start=rule_order+1):
            rule['order'] = i
    except KeyError:
        # If no order has been provided, append the new rule
        rule_order = len(role.rules) + 1
        new_rule.update({'order': rule_order})
        role.rules.append(new_rule)

    return role.__dict__


def process_delete_rule(role, rule_id):
    """Remove a existing rule from the list of rules in a RBACRole

    Args:
        role (RBACRole): RBACRole instance
        rule_id (str): Rule id

    Returns:
        dict: Updated RBACRole role dict
    """
    for rule in role.rules:
        if rule['id'] == rule_id:
            role.rules.remove(rule)
            break
    else:
        raise serializers.ValidationError(
            {'detail': _("Rule with id %s not found in the RBACRole. " %
                         rule_id)})

    # Update the order of affected rules by the rule deletion
    order = len(role.rules)
    for rule in reversed(role.rules):
        if rule['order'] == order:
            break
        rule['order'] = order
        order -= 1

    return role.__dict__


def process_change_rule_order(role, rule_id, new_order):
    """Change order of a rule in the list of rules of a RBACRole

    Args:
        role (RBACRole): RBACRole instance
        rule_id (str): Rule id
        new_order (str): New rule order

    Returns:
        dict: Updated RBACRole role dict
    """
    if new_order is None:
        raise serializers.ValidationError(
            {'detail': _("Rule order cannot be empty.")})

    new_order = int(new_order)

    if not(0 < new_order <= len(role.rules)):
        raise serializers.ValidationError(
            {'detail': _("The order must be must be a positive integer not "
                         "greater than total number of rules")})

    new_order -= 1
    old_order = None
    for rule in role.rules:
        if rule['id'] == rule_id:
            global old_order
            old_order = rule['order'] - 1

            role.rules.insert(new_order, role.rules.pop(old_order))
            break
    else:
        raise serializers.ValidationError(
            {'detail': _("Rule with id %s not found in the RBACRole" %
                         rule_id)})

    # Return the original RBACRole
    if old_order == new_order:
        return role.__dict__

    # Update the order of affected rules by the changing the rule order
    if old_order < new_order:
        start, end = old_order, new_order + 1
    else:
        start, end = new_order, old_order + 1

    for order in xrange(start, end):
            role.rules[order]['order'] = order + 1

    return role.__dict__
