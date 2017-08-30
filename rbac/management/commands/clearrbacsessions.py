# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.core.management.base import BaseCommand
from rbac.models import RbacSession


class Command(BaseCommand):
    help = "Can be run as a cronjob or directly to remove expired RBAC sessions."

    def handle(self, *args, **options):
        RbacSession.clear_expired()
