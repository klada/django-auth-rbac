# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import logging

from django.conf import settings

from .models import RbacPermissionProfile, RbacRole

logger = logging.getLogger(__name__)


class RbacSession(object):
    """
    Represents the RBAC session for a user. It allows the user to set active roles for a session. A RbacSession
    may be tied to a Django web session by passing the `django_session` argument to the constructor. This way the
    activated roles can be persisted across requests. Otherwise a new RbacSession will be created for each newly
    instanciated user (when checking permissions for the user for the first time).

    The default set of roles for a session can be controlled through the setting 'RBAC_DEFAULT_ROLES'.

    Usually the `RbacSessionMiddleware` takes care of creating/restoring RBAC sessions from the HTTP request.
    """
    DJANGO_SESSION_KEY = 'rbac_role_ids'

    def __init__(self, user, django_session=None):
        """
        :param user: The Django user (settings.AUTH_USER_MODEL) that will be using this RBAC session.
        :type user: User
        :param django_session: The Django session (`request.session`), which will store the user's active roles. If no
                               session is passed in, either all of the user's roles or only the ones from
                               `settings.RBAC_DEFAULT_ROLES` will be activated within this RBAC session.
        """
        self._active_roles = RbacRole.objects.none()
        self._active_roles_ids = None

        self._user = user
        self._django_session = django_session

        # A Django session with previously selected roles was passed in. Restore the selected roles from the session.
        if self._django_session and self.DJANGO_SESSION_KEY in self._django_session:
            role_qs = user.get_all_roles().filter(pk__in=self._django_session[self.DJANGO_SESSION_KEY])
            new_session = False
        else:
            # We are dealing with a new Django session or with a new backend session (without web context).
            # In either case we need to load the default roles for the user.
            new_session = True

            default_roles = getattr(settings, "RBAC_DEFAULT_ROLES", "all")
            # Special case: `RBAC_DEFAULT_ROLES` is not set or set to "all".
            # This means we'll load all roles into the user's session by default
            if isinstance(default_roles, str):
                if default_roles.lower() == 'all':
                    role_qs = user.get_all_roles()
                else:
                    # Invalid string, do not activate any roles
                    role_qs = RbacRole.objects.none()
                    logger.warning("Invalid value for settings.RBAC_DEFAULT_ROLES. Not loading any session roles.")
            else:
                # In case `RBAC_DEFAULT_ROLES` is set to a list of role names we'll limit the user's roles to
                # the roles specified by that setting
                role_qs = user.get_all_roles().filter(name__in=default_roles)

        self.active_roles = role_qs

        # Make this object persistent in the Django session
        if self._django_session and new_session:
            self.save()

    @property
    def active_roles(self):
        """
        Property which holds all of the roles which should be active for this session.

        :rtype: RbacRole
        """
        return self._active_roles

    @active_roles.setter
    def active_roles(self, value):
        """
        Always use this setter property for settings `active_roles` to a new value. It takes care of clearing internal
        id caches, which are usually used for faster and less complex queries.

        :param value: A QuerySet containg valid RbacRoles for this session
        :type value: QuerySet
        """
        self._active_roles = value
        self._active_roles_ids = None

    def get_active_role_ids(self):
        """
        Using `active_roles` for looking up permissions may lead to very complex and slow SQL queries. Permission
        lookups are therefore performed through role ids, instead of the role QuerySet in `self.active_roles`. The
        role ids are cached by this class and can be retrieved using this helper method.

        :return: A list of active role ids for this session
        """
        if self._active_roles_ids is None:
            self._active_roles_ids = list(self.active_roles.values_list('pk', flat=True))
        return self._active_roles_ids

    def _has_perm(self, permission):
        """
        Checks if the specified permission can be obtained within this session.

        :type permission: RbacPermission
        :rtype: bool
        """
        return RbacPermissionProfile.objects.filter(
            permission=permission,
            role__in=self.get_active_role_ids()
        ).exists()

    def save(self):
        """
        Saves the currently activated roles in the Django session.
        """
        if self._django_session:
            self._django_session[self.DJANGO_SESSION_KEY] = self.get_active_role_ids()
            self._django_session.modified = True

    @property
    def user(self):
        """
        :return: The Django user which this session belongs to.
        """
        return self._user
