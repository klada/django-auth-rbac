import inspect
import logging
import re
from django.contrib.auth.models import User
from django.contrib.auth.backends import ModelBackend
from django.contrib.contenttypes.models import ContentType
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
        
        if not isinstance(perm, models.RbacPermission):
            if not obj:
                #Also support admin-style permissions
                # applabel.(add)|(change)|(delete)_modelname
                perm_pattern = "^[A-z]+[\.]((add)|(change)|(delete))[_][A-z_]+$"
                if re.match(perm_pattern, perm):
                    splitperm = perm.split('.')
                    app_label = splitperm[0]
                    operation = splitperm[1].split('_')[0]
                    model = ''.join(splitperm[1].split('_')[1:])
                    try:
                        perm = models.RbacPermission.objects.get(
                                name = operation,
                                content_type__app_label = app_label,
                                content_type__model = model
                               )
                    except ObjectDoesNotExist:
                        logger.info("has_perm(): Permission %s not found!" %perm)
                        return False
                else:
                    #we cannot do anything useful with this permission, as
                    # we are unable to identify the corresponding model
                    logger.info("has_perm(): "
                                "You cannot omit the obj parameter when not"
                                " specifying a permission object!")   
                    return False
            else:
                try:
                    perm = models.RbacPermission.objects.get(
                            name=perm,
                            content_type=ContentType.objects.get_for_model(obj)
                           )
                except ObjectDoesNotExist:
                    logger.info("has_perm(): Permission %s not found for the"
                                " specified object!" %perm)
                    return False

        session = self._get_user_session(user_obj)

        if session._has_perm(perm):
            return True
        #make sure we are calling _has_perm() on model instance
        elif obj and hasattr(obj, "_has_perm") and not inspect.isclass(obj):
            return obj._has_perm(user_obj, perm)
        else:
            return False


    def get_all_permissions(self, user_obj, obj=None):
        """
        Either returns all permissions of the specified user or only the
        Model-permissions.
        
        Please note that when passing in an actual class instance as I{obj}
        you'll still only get the (global) Model permissions. This method will
        not return any context-specific permissions through obj._has_perm()!
        
        @rtype: QuerySet
        """
        if user_obj.is_anonymous():
            return RbacPermission.objects.none()
        
        base_qs = models.RbacPermission.objects 
        
        if obj:
            app_label = obj._meta.app_label
            if not inspect.isclass(obj):
                #We've got an instance here, but we don't deal with context-
                # permissions in this method for performance reasons.
                logger.info("get_all_permissions(): Received a class instance, but only returning (global) Model permissions!")
                model = obj.__class__.__name__
            else:
                #obj is a class
                model = obj.__name__
            
            base_qs = base_qs.filter(content_type__app_label=app_label, content_type__model=model)
        
        session = self._get_user_session(user_obj)
        return base_qs.filter(
                 rbacpermissionprofile__role__in=session.active_roles.all()
               )
        

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
