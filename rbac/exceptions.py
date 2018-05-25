# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
from django.core.exceptions import PermissionDenied

class RbacPermissionDenied(PermissionDenied):
    "The user did not have permission to do that"
    pass


class RbacRuntimeError(RuntimeError):
    "An error has ocurred at runtime."
    pass
