import inspect
import itertools
import logging
from django.contrib.auth.models import User
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ObjectDoesNotExist
from rbac import _globals, models
from rbac.models import RbacPermission, RbacPermissionProfile

logger = logging.getLogger(__name__)

class RbacUserBackend(ModelBackend):
    """
    Limitations:
        - Does not support group permissions
        - Does not support app-label permissions
    """
    def _get_user_session(self, user_obj):
        """
        Returns a RBAC session for the specified user.

        @rtype: rbac.models.RbacSession
        """
        if hasattr(_globals, '_rbac_session') and \
           isinstance(_globals._rbac_session, models.RbacSession) and \
           _globals._rbac_session.user == user_obj:
            #the session in _globals belongs to request.user
            return _globals._rbac_session
        else:
            rbac_session, created = models.RbacSession.objects.get_or_create(user=user_obj, session_key="backend") #@UnusedVariable
            return rbac_session
    
    
    def has_module_perms(self, user_obj, abb_label):
        if user_obj.is_anonymous():
            return False
        session = self._get_user_session(user_obj)
        if RbacPermissionProfile.objects.filter(role__in=session.active_roles.all(), permission__content_type__app_label=abb_label).count() > 0:
            return True
        else:
            return False


    def has_perm(self, user_obj, perm, obj=None):
        if user_obj.is_anonymous():
            return False
        
        if isinstance(perm, RbacPermission):
            verbose_perm = "%s.%s_%s" %(perm.content_type.app_label, perm.name, perm.content_type.model)
            if verbose_perm in self.get_all_permissions(user_obj):
                return True
            if hasattr(obj, "_has_perm") and not inspect.isclass(obj):
                return obj._has_perm(perm)
            else:
                return False
        elif not obj:
            return perm in self.get_all_permissions(user_obj)
        else:
            app_label = obj._meta.app_label
            if inspect.isclass(obj):
                model = obj.__name__.lower()
            else:
                model = obj.__class__.__name__.lower()
            
            perm_name = "%s.%s_%s" %(app_label, perm, model)
            if perm_name in self.get_all_permissions(user_obj):
                return True
            
            if hasattr(obj, "_has_perm") and not inspect.isclass(obj):
                try:
                    perm = RbacPermission.objects.get(
                            name=perm,
                            content_type__app_label=app_label,
                            content_type__model=model
                           )
                except ObjectDoesNotExist:
                    logger.info("has_perm(): Permission %s not found!" %perm)
                    return False
                
                return obj.has_perm(perm)
        return False

    
    def _get_all_object_permissions(self, user_obj, obj):
        """
        Please note that when passing in an actual class instance as I{obj}
        you'll still only get the (global) Model permissions. This method will
        not return any context-specific permissions through obj._has_perm()!
        
        @rtype: set
        """
        app_label = obj._meta.app_label
        if not inspect.isclass(obj):
            #We've got an instance here, but we don't deal with context-
            # permissions in this method for performance reasons.
            logger.info("_get_all_object_permissions(): Received a class instance, but only returning (global) Model permissions!")
            model = obj.__class__.__name__
        else:
            #obj is a class
            model = obj.__name__
        model = model.lower()
        
        session = self._get_user_session(user_obj)
        perms = RbacPermission.objects.filter(
                 content_type__app_label=app_label,
                 content_type__model=model,
                 rbacpermissionprofile__role__in=session.active_roles.all()
                ).values_list('name', flat=True)
        return set(itertools.imap(lambda x: '%s.%s_%s' %(app_label, x, model), perms))
 

    def get_all_permissions(self, user_obj, obj=None):
        """
        Either returns all permissions of the specified user or only the
        Model-permissions.
        
        Please note that when passing in an actual class instance as I{obj}
        you'll still only get the (global) Model permissions. This method will
        not return any context-specific permissions through obj._has_perm()!
        
        @rtype: set
        """
        if user_obj.is_anonymous():
            return set()
        
        if obj:
            return self._get_all_object_permissions(user_obj, obj)
        
        if not hasattr(user_obj, '_rbacperm_cache'):
            logger.debug('get_all_permissions(): Building permission cache for user %s' %user_obj.pk)
            session = self._get_user_session(user_obj)
            perms = RbacPermission.objects.filter(
                     rbacpermissionprofile__role__in=session.active_roles.all()
                    ).select_related(
                     'content_type'
                    ).values_list(
                     'content_type__app_label',
                     'name',
                     'content_type__model',
                    )
            user_obj._rbacperm_cache = set(itertools.imap(lambda x: '%s.%s_%s' %(x[0], x[1], x[2]), perms))
        else:
            logger.debug('get_all_permissions(): Using permission cache for user %s' %user_obj.pk)
        return user_obj._rbacperm_cache
        

class RbacRemoteUserBackend(RbacUserBackend):
    """
    This backend is to be used in conjunction with the ``RemoteUserMiddleware``
    found in the middleware module of django.contrib.auth, and is used when the
    server is handling authentication outside of Django.

    By default, the ``authenticate`` method creates ``User`` objects for
    usernames that don't already exist in the database.  Subclasses can disable
    this behavior by setting the ``create_unknown_user`` attribute to
    ``False``.
    """

    # Create a User object if not already in the database?
    create_unknown_user = False

    def authenticate(self, remote_user):
        """
        The username passed as ``remote_user`` is considered trusted.  This
        method simply returns the ``User`` object with the given username,
        creating a new ``User`` object if ``create_unknown_user`` is ``True``.

        Returns None if ``create_unknown_user`` is ``False`` and a ``User``
        object with the given username is not found in the database.
        """
        if not remote_user:
            return
        user = None
        username = self.clean_username(remote_user)

        # Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if self.create_unknown_user:
            user, created = User.objects.get_or_create(username=username)
            if created:
                user = self.configure_user(user)
        else:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                pass
        return user

    def clean_username(self, username):
        """
        Performs any cleaning on the "username" prior to using it to get or
        create the user object.  Returns the cleaned username.

        By default, returns the username unchanged.
        """
        return username

    def configure_user(self, user):
        """
        Configures a user after creation and returns the updated user.

        By default, returns the user unmodified.
        """
        return user
