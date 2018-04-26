"""
Automatically creates permissions for non-system apps after calling migrate.
"""
from django.db.models import signals
from django.apps import apps
from django.dispatch import receiver


def _get_all_permissions(obj_meta_class):
    """
    Returns (name, description) for all permissions in the given opts.
    """
    #Skip proxy objects
    if hasattr(obj_meta_class, 'proxy') and obj_meta_class.proxy:
        return []

    perms = []
    for action in ('add', 'change', 'delete'):
        perms.append((action, u'Can %s %s' % (action, obj_meta_class.verbose_name_raw)))
    return perms + list(obj_meta_class.permissions)


def create_permissions(app_config, verbosity, **kwargs):
    """
    Creates all of the permissions defined in a model and a set of default
    permissions.
    """
    if not app_config.models_module:
        return
    
    from django.contrib.contenttypes.models import ContentType
    from rbac.models import RbacPermission

    #do not add permissions for rbac and django models
    #@TODO: needed for Django admin
    #if app.__name__ == "rbac.models" or \
    #   app.__name__.startswith("django"):
    #    return
    app_models = app_config.get_models()

    # This will hold the permissions we're looking for as
    # (content_type, (name, description))
    searched_perms = list()
    # The codenames and ctypes that should exist.
    ctypes = set()
    for klass in app_models:
        ctype = ContentType.objects.get_for_model(klass)
        ctypes.add(ctype)
        for perm in _get_all_permissions(klass._meta):
            searched_perms.append((ctype, perm))

    # Find all the Permissions that have a content_type for a model we're
    # looking for.  We don't need to check for names since we already have
    # a list of the ones we're going to create.
    all_perms = set(RbacPermission.objects.filter(
        content_type__in=ctypes,
    ).values_list(
        "content_type", "name"
    ))
    objs = []
    for ctype, (name, description) in searched_perms:
        if (ctype.pk, name) not in all_perms:
            objs.append(RbacPermission(content_type=ctype, name=name, description=description))
    RbacPermission.objects.bulk_create(objs)
    if verbosity >= 2:
        for obj in objs:
            print("Adding permission '%s'" % obj)


# Do not add permissions to "auth_permission", as it is not used
signals.post_migrate.disconnect(dispatch_uid="django.contrib.auth.management.create_permissions")
