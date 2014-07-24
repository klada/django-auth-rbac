from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist
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
            rbac_session_id = request.session.get('_rbac_session_id', None)
        except AttributeError:
            raise ImproperlyConfigured(
                "The RBAC session middleware requires the"
                " session middleware to be installed.  Edit your"
                " MIDDLEWARE_CLASSES setting to insert"
                " 'django.contrib.sessions.middleware.SessionMiddleware'"
                " before the RbacSessionMiddleware class.")

        if not rbac_session_id:
            rbac_session = RbacSession.objects.create(user=request.user, backend_session=None)
        else:
            try:
                rbac_session = RbacSession.objects.get(id=rbac_session_id, user=request.user)
            except ObjectDoesNotExist:
                rbac_session = RbacSession.objects.create(user=request.user, backend_session=None)          
                
        request.session['_rbac_session_id'] = rbac_session.id
        request.user._rbac_session = rbac_session
