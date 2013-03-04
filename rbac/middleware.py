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
            rbac_session_id = request.session.get('_rbac_session_id', 0)
        except AttributeError:
            raise ImproperlyConfigured(
                "The RBAC session middleware requires the"
                " session middleware to be installed.  Edit your"
                " MIDDLEWARE_CLASSES setting to insert"
                " 'django.contrib.sessions.middleware.SessionMiddleware'"
                " before the RbacSessionMiddleware class.")

        if rbac_session_id == 0:
            _globals._rbac_session = RbacSession.objects.create(user=request.user, backend_session=False)
            request.session['_rbac_session_id'] = _globals._rbac_session.id
        else:
            _globals._rbac_session = RbacSession.objects.get(id=rbac_session_id)
            

    def process_response(self, request, response):
        #clean up _globals
        _globals._rbac_session=None
        return response
