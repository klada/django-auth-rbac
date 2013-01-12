from django.core.exceptions import PermissionDenied

class RbacPermissionDenied(PermissionDenied):
    "The user did not have permission to do that"
    pass


class RbacRuntimeError(RuntimeError):
    "An error has ocurred at runtime."
    pass
