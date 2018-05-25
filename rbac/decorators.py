# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.contrib.auth.decorators import user_passes_test
from rbac.exceptions import RbacPermissionDenied


def rbac_permission_required(operation, model):
    """
    View decorator which was ment as a replacement for Django's
    I{permission_required} decorator.

    @TODO: Deprecate this decorator, as it has no actual benefit over
           Django's I{permission_required}.
    """
    def check_perms(user):
        # First check if the user has the permission (even anon users)
        if user.has_perm(operation, model):
            return True
        else:
            raise RbacPermissionDenied()
    return user_passes_test(check_perms)
