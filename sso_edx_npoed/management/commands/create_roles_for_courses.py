#! /usr/bin/python
# -*- coding: utf-8 -*-
from django.conf import settings
from django.core.management.base import BaseCommand

from sso_edx_npoed.utils import create_forum_roles_and_permissions_for_cours


class Command(BaseCommand):
    help = 'Find all cources without forum roles and create this roles.'

    def handle(self, *args, **options):
        
        self.stdout.write('Create roles')
