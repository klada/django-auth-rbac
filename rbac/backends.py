# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

import inspect
import logging

from django.contrib.auth.backends import ModelBackend, RemoteUserBackend
from django.core.exceptions import ObjectDoesNotExist

from .models import RbacPermission, RbacPermissionProfile
from .session import RbacSession

logger = logging.getLogger(__name__)


class RbacUserBackendMixin(object):
    """
    Mixin class which adds the magic required for RBAC permission lookups to other user backends.

    Limitations:
        - Does not support group permissions
    """
    def _get_user_session(self, user_obj):
        """
        Returns a RBAC session for the specified user.

        :rtype: rbac.session.RbacSession
        """
        if hasattr(user_obj, '_rbac_session') and isinstance(user_obj._rbac_session, RbacSession):
            # the session belongs to request.user
            assert user_obj._rbac_session.user == user_obj
            return user_obj._rbac_session
        else:
            rbac_session = RbacSession(user=user_obj)
            logger.info("Using RBAC backend session for user %s." %user_obj.id)
            return rbac_session
    
    def has_module_perms(self, user_obj, app_label):
        if user_obj.is_anonymous:
            return False
        
        if not hasattr(user_obj, '_rbac_module_permission_cache'):
            logger.debug('has_module_perms(): Building app-label permission cache for user %s' %user_obj.pk)
            session = self._get_user_session(user_obj)
            app_labels = RbacPermissionProfile.objects.filter(
                             role__in=session.get_active_role_ids()
                         ).values_list(
                             'permission__content_type__app_label',
                             flat=True
                         ).distinct()
            user_obj._rbac_module_permission_cache = set(app_labels)
        else:
            logger.debug('has_module_perms(): Using app-label permission cache for user %s' %user_obj.pk)
        
        return app_label in user_obj._rbac_module_permission_cache

    def has_perm(self, user_obj, perm, obj=None):
        if user_obj.is_anonymous:
            return False
        
        if isinstance(perm, RbacPermission):
            verbose_perm = "%s.%s_%s" %(perm.content_type.app_label, perm.name, perm.content_type.model)
            if verbose_perm in self.get_all_permissions(user_obj):
                return True
            if hasattr(obj, "_has_perm") and not inspect.isclass(obj):
                return obj._has_perm(user_obj, perm)
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
                
                return obj._has_perm(user_obj, perm)
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
                 rbacpermissionprofile__role__in=session.get_active_role_ids()
                ).values_list('name', flat=True)
        return set(map(lambda x: '%s.%s_%s' %(app_label, x, model), perms))

    def get_all_permissions(self, user_obj, obj=None):
        """
        Either returns all permissions of the specified user or only the
        Model-permissions.
        
        Please note that when passing in an actual class instance as I{obj}
        you'll still only get the (global) Model permissions. This method will
        not return any context-specific permissions through obj._has_perm()!
        
        @rtype: set
        """
        if user_obj.is_anonymous:
            return set()
        
        if obj:
            return self._get_all_object_permissions(user_obj, obj)
        
        if not hasattr(user_obj, '_rbacperm_cache'):
            logger.debug('get_all_permissions(): Building permission cache for user %s' %user_obj.pk)
            session = self._get_user_session(user_obj)
            perms = RbacPermission.objects.filter(
                     rbacpermissionprofile__role__in=session.get_active_role_ids()
                    ).select_related(
                     'content_type'
                    ).values_list(
                     'content_type__app_label',
                     'name',
                     'content_type__model',
                    )
            user_obj._rbacperm_cache = set(map(lambda x: '%s.%s_%s' %(x[0], x[1], x[2]), perms))
        else:
            logger.debug('get_all_permissions(): Using permission cache for user %s' %user_obj.pk)
        return user_obj._rbacperm_cache
        

class RbacUserBackend(RbacUserBackendMixin, ModelBackend):
    """
    A version of `django.contrib.auth.backends.ModelBackend` with support for RBAC permission lookups.
    """
    pass


class RbacRemoteUserBackend(RbacUserBackendMixin, RemoteUserBackend):
    """
    A version of `django.contrib.auth.backends.RemoteUserBackend` with support for RBAC permission lookups.
    """
    pass
