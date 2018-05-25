django-auth-rbac
================

An attempt of implementing role-based access control (ANSI/INCITS 359-2004) for Django

Supported RBAC features:

* Core RBAC
* Hierarchical RBAC
* Static separation of duty (SSD)

Basic concepts
--------------
### Roles
Roles provide a level of indirection between users and permissions, typically representing job functions. A role may also have multiple child roles, allowing a complex role hierarchy. Permissions from child roles are inherited by parent roles.

### Permissions
According to the RBAC standard a permission is an operation on an object. In django-auth-rbac an object is a model, which means a permission is an operation on a model. Operations can be represented by a string, such as 'change' or 'delete'.

The actual permission is an object, storing the model information through Django's contenttype framework and the name of the operation.

### Sessions
An RBAC session is started whenever a user logs in. Within this session the user can choose which roles he wants to activate. By default all of the user's roles are activated. This behavior can be controlled through the setting `RBAC_DEFAULT_ROLES`.

Requirements
------------
* Django 1.10 or higher
* Django components:
    - Contenttypes framework
    - Session framework

Installation
------------
1. Add *rbac* to `settings.INSTALLED_APPS`
2. Set `AUTHENTICATION_BACKENDS` to *rbac.backends.RbacUserBackend* or any subclass of *RbacUserBackend*.
3. Add *rbac.middleware.RbacSessionMiddleware* to `MIDDLEWARE`.
4. **optional:** Configure `RBAC_DEFAULT_ROLES`. This option accepts a tuple of role names which will be activated by default in RBAC sessions. If you omit this setting then all of the user's roles will be activated within a session.
5. **optional:** If you are using a custom user class, make sure it inherits from *rbac.users.AbstractRbacUser* and set `AUTH_USER_MODEL` to your custom user class. If you omit this setting your user objects will be instances of *RbacUser*, a subclass of django.contrib.auth.models.AbstractUser.


Usage
-----
You can use django-auth-rbac pretty much like *django.contrib.auth*. The syntax of permission lookups is identical to *django.contrib.auth*. You can even control access in Django's built-in admin with RBAC permissions. The parameters for *user.has_perm()* remain the same as well:

    user = request.user
    obj = get_object_or_404(ExampleModel, pk=1)
    if user.has_perm('change', obj):
        #do something....
        pass
    else:
        raise PermissionDenied()


Since RBAC permissions are tied to a specific model you should not add permissions manually. They are added automatically when running *syncdb*. Just like with *django.contrib.auth* you can specify additional model-permissions [directly in the model's **Meta** class](http://docs.djangoproject.com/en/1.5/ref/models/options/#permissions).


Limitations
-----------
* Per-object permissions are not directly supported (only per-model permissions). However, it is possible to add a *_has_perm()* method to your models which can be used for checking context-sensitive permissions.


