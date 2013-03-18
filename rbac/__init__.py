import sys
from django.conf import settings

# Fall back to 'rbac.RbacUser' if
# settings.AUTH_USER_MODEL is not defined.
if settings.AUTH_USER_MODEL.lower() == 'auth.user' \
   or settings.AUTH_USER_MODEL == '':
    settings.AUTH_USER_MODEL = 'rbac.rbacuser'

if 'test' in sys.argv:
    settings.RBAC_SKIP_TESTS = False
    if settings.AUTH_USER_MODEL.lower() != 'rbac.rbacuser':
        if 'rbac' in sys.argv:
            print "NOTICE: Using RBAC user model for testing..."
            settings.AUTH_USER_MODEL = 'rbac.rbacuser'
        else:
            print "WARNING: Skipping RBAC tests."
            settings.RBAC_SKIP_TESTS = True

if settings.AUTH_USER_MODEL.lower() == 'rbac.rbacuser':
    from rbac.users import RbacUser

