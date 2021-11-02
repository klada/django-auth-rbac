# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from django.apps import AppConfig
from django.db.models.signals import post_migrate
from rbac.management import create_permissions


class RbacConfig(AppConfig):
    default_auto_field = 'django.db.models.AutoField'
    name = 'rbac'
    verbose_name = 'RBAC'

    def ready(self):
        post_migrate.connect(create_permissions,
            dispatch_uid='rbac.management.create_permissions'
        )
