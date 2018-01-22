# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render
from django.http import Http404, HttpResponseRedirect
from django.views.decorators.cache import never_cache
from rbac.forms import ActiveSessionRoleForm

from .session import RbacSession


@never_cache
def set_active_session_roles(request):
    """
    Shows a form allowing the user to set active roles for the current RBAC
    session.
    """
    if not hasattr(request.user, '_rbac_session') or \
       not isinstance(request.user._rbac_session, RbacSession):
        #raise ImproperlyConfigured(
        #    "No active RBAC session found. Make sure you have"
        #    " 'rbac.middleware.RbacSessionMiddleware' in your"
        #    " MIDDLEWARE_CLASSES.")
        raise Http404()

    rbac_session = request.user._rbac_session
    if request.method == "POST":
        redir = request.session.get('redir', '/')
        #check if cancel button was clicked
        if "cancel" in request.POST:
            return HttpResponseRedirect(redir)

        my_form = ActiveSessionRoleForm(rbac_session, request.POST)
        if my_form.is_valid():
            my_form.save()
            return HttpResponseRedirect(redir)
    else:
        redir = request.GET.get('next', None)
        if not redir:
            redir = request.META.get('HTTP_REFERER', '/')
        #Store redir in session, because GE/REFERER will be lost when
        # POSTING form data.
        request.session['redir'] = redir
        my_form = ActiveSessionRoleForm(rbac_session)

    return render(request, 'rbac/set_active_roles.html', {'form': my_form})

