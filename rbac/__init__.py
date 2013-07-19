from django.conf import settings

if settings.AUTH_USER_MODEL.lower() == 'rbac.rbacuser':
    from rbac.users import RbacUser
