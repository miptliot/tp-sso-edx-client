# coding: utf-8

import logging
from uuid import uuid4
from django.conf import settings
from django.contrib.sites.models import Site
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = u'Команда для обновления дефолтных сайтов по данным из файла настроек'

    def handle(self, *args, **options):
        for attr in ('SITE_ID', 'LMS_BASE', 'CMS_BASE'):
            if not getattr(settings, attr, None):
                logging.error('Failed to update sites: {} is not defined'.format(attr))
                return
        self.update_site(int(settings.SITE_ID), settings.LMS_BASE)
        self.update_site(int(settings.SITE_ID) + 1, settings.CMS_BASE)

    def update_site(self, site_id, domain):
        site = Site.objects.filter(domain=domain).first()
        if site and site.id != site_id:
            Site.objects.filter(domain=domain).update(
                domain='{}.{}'.format(str(uuid4())[:8], domain),
            )
        Site.objects.update_or_create(id=site_id, defaults={
            'domain': domain,
            'name': domain
        })
