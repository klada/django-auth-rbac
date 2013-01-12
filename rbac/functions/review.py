from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from rbac import models


def AssignedUsers(role):
    """
    Returns the users which are assigned to the specified role.
    
    @type    role: RbacRole
    @rtype: QuerySet
    """
    return get_user_model().objects.filter(rbacuserassignment__roles=role)


def AssignedRoles(user):
    """
    Returns the roles assigned to a user.
    
    @rtype: QuerySet
    """
    return models.RbacRole.objects.filter(rbacuserassignment__user=user)


def RolePermissions(role):
    """
    Returns the permissions granted to or inherited by a role.
    
    @note: Uses the RbacPermissionProfile cache model
    @rtype: QuerySet
    """
    return models.RbacPermission.objects.filter(rbacpermissionprofile__role=role)


def UserPermissions(user):
    """
    Returns the permissions which the user gets through his/her authorized roles.
    
    @note: Uses the RbacPermissionProfile cache model
    @rtype: QuerySet
    """
    return models.RbacPermission.objects.filter(rbacpermissionprofile__role__rbacuserassignment__user=user)


def SessionRoles(session):
    """
    Returns the active roles associated with an RBAC session.
    
    @rtype: QuerySet
    """
    return models.RbacRole.objects.filter(rbacsession=session)
    

def SessionPermissions(session):
    """
    Returns the permissions assigned to a session's active roles.
    
    @rtype: QuerySet
    """
    return models.RbacPermission.objects.filter(rbacpermissionprofile__role__rbacsession=session)


def RoleOperationsOnObject(role, obj):
    """
    Returns the operations a given role is permitted to perform on an object.
    
    @rtype: list
    """
    ctype = ContentType.objects.get_for_model(obj)
    return models.RbacPermission.objects.filter(
            rbacpermissionprofile__role=role,
            permission__content_type=ctype
           ).distinct().values_list('name', flat=True)

    

def UserOperationsOnObject(user, obj):
    """
    Returns the list of operations a given user is permitted to perform on an object.
    
    @rtype: list
    """
    ctype = ContentType.objects.get_for_model(obj)
    return models.RbacPermission.objects.filter(
            rbacpermissionprofile__role__rbacuserassignment__user=user,
            permission__content_type=ctype
           ).distinct().values_list('name', flat=True)


def AuthorizedUsers(role):
    """
    Returns the set of users authorized to a given role.
    
    @rtype: QuerySet
    """
    return get_user_model().objects.filter(rbacuserassignment__roles__children_all=role)


def AuthorizedRoles(user):
    """
    Returns the set of roles authorized for a given user.
    
    @rtype: QuerySet
    """
    return models.RbacRole.objects.filter(Q(parents_all__rbacuserassignment__user=user) |
                                          Q(rbacuserassignment__user=user))
