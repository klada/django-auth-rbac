from django.contrib.auth.decorators import user_passes_test
from rbac import _globals
from rbac.exceptions import RbacPermissionDenied, RbacRuntimeError
from rbac.models import RbacSession, RbacPermission

def rbac_permission_required(operation, model):
    def check_perms(user):
        # First check if the user has the permission (even anon users)
        if user.has_perm(operation, model):
            return True
        else:
            raise RbacPermissionDenied()
    return user_passes_test(check_perms)



def rbac_model_permission_required(operation):
    """
    This decorator offers RBAC functionality for methods of Django models.

    An operation can be something like 'edit', 'modify' or whatever you prefer.
    The operation will be translated to an RBAC permission using the following
    schema:

        permission.name = Model._meta.db_table+'_'+operation

    This means that this only works on a per-class basis!

    If you need to call a model's method without RBAC context (e.g. from an
    admin shell) you can pass the parameter "disable_rbac=True" to the medhod.


    @raise  RbacPermissionDenied: When the user was not authorized to perform
                                  the operation.
    @raise RbacRuntimeError: When this decorator was used on non-Django models.
    """
    def _decorator(_method_func):
        #print "decorator"
        def _method(*args, **kwargs):
            from django.contrib.contenttypes.models import ContentType
            disable_rbac = kwargs.pop('disable_rbac', False)
            if disable_rbac:
                return _method_func(*args, **kwargs)
            
            try:
                self = args[0]
                ctype = ContentType.objects.get_for_model(self)
                perm = RbacPermission.objects.get(
                         name=operation,
                         content_type=ctype
                       )
            except Exception:
                raise RbacRuntimeError(
                    "You can only use this decorator on Django models!"
                    )
            print perm
            
            if hasattr(_globals, '_rbac_session') and \
               isinstance(_globals._rbac_session, RbacSession):
                if _globals._rbac_session.user.has_perm(perm, self):
                    return _method_func(*args, **kwargs)
                else:
                    raise RbacPermissionDenied("Not authorized.")
            else:
                raise RbacRuntimeError("No valid RBAC session found!")
        return _method
    return _decorator

