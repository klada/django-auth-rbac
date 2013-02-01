from django.db import models
from django.conf import settings

class AbstractRbacUser(models.Model):
    """
    This class can be used as a base class for defining custom User classes
    whenever 'django.contrib.auth.models.User' cannot be used for whatever
    reasons.

    It does not provide any properties at all - only a minimum set of methods
    which are required for RBAC operations. It is up to you to define the
    properties which are needed to work with your application or with Django's
    build-in admin.
    """
    __rbac_backend = None
    USERNAME_FIELD = 'id'
    REQUIRED_FIELDS = []
    
    class Meta:
        abstract = True

    def is_anonymous(self):
        """
        Always returns False. This is a way of comparing User objects to
        anonymous users.
        """
        return False

    def is_authenticated(self):
        """
        Always return True. This is a way to tell if the user has been
        authenticated in templates.
        """
        return True

    def get_all_roles(self):
        """
        Returns a list of roles which are assigned to this user. This list will
        be used for providing role choices in RbacSessions, for example.

        By default we only query the RbacUserAssignment for roles. If you have
        any other sources for roles you can override this method. You just need
        to make sure that this method returns a QuerySet!

        @rtype: QuerySet
        """
        from rbac.models import RbacRole
        return RbacRole.objects.filter(rbacuserassignment__user=self)

    def get_all_permissions(self, obj=None):
        if not self.__rbac_backend:
            from rbac.backends import RbacUserBackend
            self.__rbac_backend = RbacUserBackend()
        return self.__rbac_backend.get_all_permissions(self, obj)

    def has_perm(self, perm, obj=None):
        """
        Returns True if the user has the specified permission. This method
        only uses the RbacUserBackend for checking permissions.
        """
        if not self.__rbac_backend:
            from rbac.backends import RbacUserBackend
            self.__rbac_backend = RbacUserBackend()
        return self.__rbac_backend.has_perm(self, perm, obj)

    def has_perms(self, perm_list, obj=None):
        """
        Returns True if the user has each of the specified permissions. If
        object is passed, it checks if the user has all required perms for this
        object.
        """
        for perm in perm_list:
            if not self.has_perm(perm, obj):
                return False
        return True

    def has_module_perms(self, app_label):
        """
        Returns True if the user has any permission in the specified app.
        """
        if not self.__rbac_backend:
            from rbac.backends import RbacUserBackend
            self.__rbac_backend = RbacUserBackend()
        return self.__rbac_backend.has_module_perms(self, app_label)


#Only define RbacUser when it is actually used. This avoids some ImportErrors
# when using a custom user class.
if settings.AUTH_USER_MODEL == "RbacUser":
    from django.contrib.auth.models import AbstractUser

    class RbacUser(AbstractUser):
        """
        Adds extra RBAC functionality to Django's built-in User class.
        
        All RBAC-models will use this model when using 'django.contrib.auth'.
        """
        groups = None
        user_permissions = None
        __rbac_backend = None
        
        class Meta:
            app_label = 'rbac'
            db_table = 'auth_rbac_user'

        def get_all_roles(self):
            """
            Returns a list of roles which are assigned to this user. This list will
            be used for providing role choices in RbacSessions, for example.

            By default we only query the RbacUserAssignment for roles. If you have
            any other sources for roles you can override this method. You just need
            to make sure that this method returns a QuerySet!

            @rtype: QuerySet
            """
            from rbac.models import RbacRole
            return RbacRole.objects.filter(rbacuserassignment__user=self)


        def get_all_permissions(self, obj=None):
            if not self.__rbac_backend:
                from rbac.backends import RbacUserBackend
                self.__rbac_backend = RbacUserBackend()
            return self.__rbac_backend.get_all_permissions(self)
