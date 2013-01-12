from threading import local
from django.conf import settings

# Fall back to 'rbac.RbacUser' if
# settings.AUTH_USER_MODEL is not defined.
if settings.AUTH_USER_MODEL == 'auth.User' \
   or settings.AUTH_USER_MODEL == '':
    settings.AUTH_USER_MODEL = 'rbac.RbacUser'

if settings.AUTH_USER_MODEL == 'rbac.RbacUser':
    from rbac.users import RbacUser

_globals=local()
