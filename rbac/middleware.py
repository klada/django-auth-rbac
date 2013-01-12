from django.core.exceptions import ImproperlyConfigured
from rbac import _globals
from rbac.models import RbacSession

class RbacSessionMiddleware(object):
    def process_request(self, request):
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                "The RBAC session middleware requires the"
                " authentication middleware to be installed.  Edit your"
                " MIDDLEWARE_CLASSES setting to insert"
                " 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before the RbacSessionMiddleware class.")
        elif request.user.is_anonymous():
            #We do not need to initialize RbacSession for anonymous users
            return
        
        try:
            if not request.session.session_key:
                request.session.create()
            my_session_key = request.session.session_key
        except AttributeError:
            raise ImproperlyConfigured(
                "The RBAC session middleware requires the"
                " session middleware to be installed.  Edit your"
                " MIDDLEWARE_CLASSES setting to insert"
                " 'django.contrib.sessions.middleware.SessionMiddleware'"
                " before the RbacSessionMiddleware class.")

        _globals._rbac_session, created = RbacSession.objects.get_or_create(user=request.user, session_key=my_session_key) #@UnusedVariable


    def process_response(self, request, response):
        #clean up _globals
        _globals._rbac_session=None
        return response
