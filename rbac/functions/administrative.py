from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.contrib.contenttypes.models import ContentType
from rbac import models


def AddUser(user):
    pass


def DeleteUser(user):
    pass


def AddRole(role_name):
    models.RbacRole.objects.create(name=role_name)


def DeleteRole(role_name):
    models.RbacRole.objects.get(name=role_name).delete()


def AssignUser(user, role):
    """
    @raise ValidationError: When SSD is active.
    @rtype: bool
    """
    obj, created = models.RbacUserAssignment.objects.get_or_create(user=user) # @UnusedVariable
    if obj.roles.filter(pk=role.pk).count() > 0:
        return False
    else:
        obj.roles.add(role)
        return True


def DeassignUser(user, role):
    try:
        ua = models.RbacUserAssignment.objects.get(user=user)
    except ObjectDoesNotExist:
        return False
    
    if ua.roles.filter(id=role.id).count() > 0:
        ua.roles.remove(role)
        return True
    else:
        return False


def GrantPermission(model, operation, role):
    ctype = ContentType.objects.get_for_model(model)
    rbac_perm, created = models.RbacPermission.objects.get_or_create( # @UnusedVariable
                          name=operation,
                          content_type=ctype
                         )
    role.permissions.add(rbac_perm)


def RevokePermission(model, operation, role):
    ctype = ContentType.objects.get_for_model(model)

    try:
        rbac_perm = models.RbacPermission.objects.get(
                     name=operation,
                     content_type=ctype
                    )
    except ObjectDoesNotExist:
        return
    else:
        role.permissions.remove(rbac_perm)


def AddInheritance(role_asc, role_desc):
    """
    Establishes a new immediate inheritance relationship between the existing
    roles role_asc and role_desc.
    
    role_asc >> role_desc
    
    @rtype: bool
    """
    if role_desc in role_asc.get_all_parents():
        #cycle
        return False
    
    if role_desc in role_asc.get_direct_children():
        #already a direct descendant
        return False
    
    role_asc.children.add(role_desc)
    return True


def DeleteInheritance(role_asc, role_desc):
    """
    Deletes an existing immediate inheritance relationship between the existing
    roles role_asc and role_desc.
    
    role_asc >> role_desc.
    
    @rtype: bool
    """
    if role_desc in role_asc.get_direct_children():
        role_asc.children.remove(role_desc)
        return True
    else:
        return False


def AddAscendant(role_asc_name, role_desc):
    """
    Creates a new role with the name role_asc_name, and inserts it in the role
    hierarchy as an immediate ascendant of the existing role role_desc.

    @param role_asc_name: The name of the ascendend role
    @type role_asc_name: string
    @rtype: bool
    """
    role_asc = models.RbacRole()
    role_asc.name = role_asc_name
    try:
        role_asc.save()
    except ValidationError:
        return False
    else:
        return AddInheritance(role_asc, role_desc)


def AddDescendant(role_asc, role_desc_name):
    """
    Creates a new role with the name role_desc_name, and inserts it in the role
    hierarchy as an immediate descendant of the existing role role_asc.

    @param role_desc_name: The name of the descendend role
    @type role_desc_name: string
    @rtype: bool
    """
    role_desc = models.RbacRole()
    role_desc.name = role_desc_name
    try:
        role_desc.save()
    except ValidationError:
        return False
    else:
        return AddInheritance(role_asc, role_desc)

