import json
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.core.management.base import BaseCommand
from third_party_auth.models import OAuth2ProviderConfig


class Command(BaseCommand):
    def handle(self, *args, **options):
        current_clients = {i.slug: i for i in OAuth2ProviderConfig.objects.current_set()}
        data = [
            (
                'LMS',
                'sso_tp-oauth2', 
                getattr(settings, 'LMS_SOCIAL_AUTH_SSO_TP_OAUTH2_KEY', None), 
                getattr(settings, 'LMS_SOCIAL_AUTH_SSO_TP_OAUTH2_SECRET', None),
            ),
            (
                'CMS',
                'sso_tp_cms-oauth2', 
                getattr(settings, 'CMS_SOCIAL_AUTH_SSO_TP_OAUTH2_KEY', None), 
                getattr(settings, 'CMS_SOCIAL_AUTH_SSO_TP_OAUTH2_SECRET', None),
            ),
        ]
        data = filter(lambda x: all(x), data)
        for name, slug, key, secret in data:
            backend = current_clients.get(slug)
            obj_dict = self.get_obj_dict(name, slug, key, secret)
            if not backend:
                OAuth2ProviderConfig.objects.create(**obj_dict)
            else:
                update = False
                for k, v in obj_dict.items():
                    if getattr(backend, k) != obj_dict[k]:
                        update = True
                        setattr(backend, k, obj_dict[k])
                if update:
                    backend.save()

    def get_obj_dict(self, name, slug, key, secret):
        return {
            'name': name,
            'slug': slug,
            'backend_name': slug,
            'enabled': True,
            'site': Site.objects.get_current(),
            'key': key,
            'secret': secret,
            'other_settings': json.dumps({'use_for_cms': name == 'CMS'}),
        }
