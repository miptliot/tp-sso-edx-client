import logging
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    def handle(self, *args, **options):
        User = get_user_model()
        username = getattr(settings, 'SUPERUSER_USERNAME', '')
        email = getattr(settings, 'SUPERUSER_EMAIL', '')
        password = getattr(settings, 'SUPERUSER_PASSWORD', '')

        for attr in ['username', 'email', 'password']:
            if not locals().get(attr):
                logging.error('SUPERUSER_{} is not defined'.format(attr.upper()))
                exit(1)

        user = User.objects.filter(username=username).first()
        if user:
            if not (user.is_superuser and user.is_staff):
                user.is_superuser = True
                user.is_staff = True
                user.save()
        else:
            if not User.objects.filter(email=email).exists():
                User.objects.create_superuser(username, email, password)
            else:
                logging.error('Failed to create superuser: user with email {} already exists with another username'.
                              format(email))
                exit(1)
