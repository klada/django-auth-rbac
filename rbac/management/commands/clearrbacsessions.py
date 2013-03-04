from django.core.management.base import NoArgsCommand
from rbac.models import RbacSession


class Command(NoArgsCommand):
    help = "Can be run as a cronjob or directly to remove expired RBAC sessions."

    def handle_noargs(self, **options):
        RbacSession.clear_expired()