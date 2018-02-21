# -*- coding: utf-8 -*-
"""
Contains utilities for testing YOUR application.
"""
from __future__ import print_function, unicode_literals
from django.db.models import signals
from rbac import models


class DisableRbacValidationContextManager(object):
    """
    A context manager which temporarily disables all RBAC validation. This can be useful in test cases, where
    you are loading large role graphs through fixtures. In such a scenario the validation can take quite a bit of time,
    as it takes place for every role object in the fixture file. As a result your test cases run slower.

    This is where this context manager comes in handy::

        from rbac.utils.testing import DisableRbacValidationContextManager

        class MyTestCase(TestCase):
            fixtures = [
                "large_role_graph.json",
            ]

            @classmethod
            def setUpClass(cls):
                with DisableRbacValidationContextManager():
                    super(MyTestCase, cls).setUpClass()

    @attention: The required caches are set up when leaving the context manager. Permission lookup will not work within
    the context manager!
    """

    M2M_SIGNALS = (
        {
            "receiver": models._rbac_role_permissions_changed,
            "sender": models.RbacRole.permissions.through,
            "dispatch_uid": "rbac.rbac_role_permissions_changed"
        },
        {
            "receiver": models._rbac_role_children_changed,
            "sender": models.RbacRole.children.through,
            "dispatch_uid": "rbac.rbac_role_children_changed"
        },
        {
            "receiver": models._rbac_role_children_validate,
            "sender": models.RbacRole.children.through,
            "dispatch_uid": "rbac.rbac_role_children_validate"
        },
        {
            "receiver": models._rbac_ssd_validation,
            "sender": models.RbacSsdSet.roles.through,
            "dispatch_uid": "rbac.rbac_ssd_validation"
        },
        {
            "receiver": models._rbac_ssd_enforcement,
            "sender": models.RbacUserAssignment.roles.through,
            "dispatch_uid": "rbac.rbac_ssd_enforcement"
        },
    )

    def __enter__(self):
        for signal_kwargs in self.M2M_SIGNALS:
            signals.m2m_changed.disconnect(**signal_kwargs)

    def __exit__(self, *args):
        for signal_kwargs in self.M2M_SIGNALS:
            signals.m2m_changed.connect(**signal_kwargs)
        models.RbacRoleProfile.create()
        models.RbacPermissionProfile.create()
