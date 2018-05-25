# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.core.exceptions import ImproperlyConfigured
from django.utils.deprecation import MiddlewareMixin

from rbac.session import RbacSession


class RbacSessionMiddleware(MiddlewareMixin):
    @staticmethod
    def process_request(request):
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                "The RBAC session middleware requires the"
                " authentication middleware to be installed.  Edit your"
                " MIDDLEWARE setting to insert"
                " 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before the RbacSessionMiddleware class.")
        elif request.user.is_anonymous:
            # We do not need to initialize RbacSession for anonymous users
            return

        if not hasattr(request, 'session'):
            raise ImproperlyConfigured(
                "The RBAC session middleware requires the"
                " session middleware to be installed.  Edit your"
                " MIDDLEWARE setting to insert"
                " 'django.contrib.sessions.middleware.SessionMiddleware'"
                " before the RbacSessionMiddleware class.")

        request.user._rbac_session = RbacSession(request.user, request.session)
