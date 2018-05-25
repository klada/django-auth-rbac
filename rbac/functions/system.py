from django.core.exceptions import ObjectDoesNotExist
from rbac import models


def CreateSession(user, session_key):
    """
    @TODO: DSD
    @rtype: bool
    """
    session, created = models.RbacSession.objects.get_or_create(user=user, session_key=session_key) # @UnusedVariable
    return created


def DeleteSession(user, session_key):
    try:
        models.RbacSession.objects.get(user=user, session_key=session_key).delete()
    except ObjectDoesNotExist:
        return False
    else:
        return True


def AddActiveRole(user, session_key, role):
    """
    @TODO: DSD
    """
    session = models.RbacSession.objects.get(user=user, session_key=session_key)
    session.active_roles.add(role)


def DropActiveRole(user, session_key, role):
    session = models.RbacSession.objects.get(user=user, session_key=session_key)
    session.active_roles.remove(role)


def CheckAccess(session, operation, model):
    """
    @TODO: fix this
    """
    return session.user.has_perm(operation, model)


def AssignedRoles(user):
    """
    @rtype: QuerySet
    """
    return models.RbacRole.objects.filter(rbacuserassignment__user=user)


def SessionPermissions(session):
    return models.RbacPermission.objects.filter(rbacpermissionprofile__role__in=session.active_roles.all())
