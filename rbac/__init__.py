import sys
from threading import local
from django.conf import settings

# Fall back to 'rbac.RbacUser' if
# settings.AUTH_USER_MODEL is not defined.
if settings.AUTH_USER_MODEL.lower() == 'auth.user' \
   or settings.AUTH_USER_MODEL == '':
    settings.AUTH_USER_MODEL = 'rbac.rbacuser'

if 'test' in sys.argv:
    settings.AUTH_USER_MODEL = 'rbac.rbacuser'

if settings.AUTH_USER_MODEL.lower() == 'rbac.rbacuser':
    from rbac.users import RbacUser

_globals=local()
