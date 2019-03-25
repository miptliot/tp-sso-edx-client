# coding: utf-8

import json
import logging

from django.conf import settings
from django.contrib.sites.models import Site

from social_core.utils import handle_http_errors
from social_core.backends.oauth import BaseOAuth2

from ..utils import get_site

log = logging.getLogger(__name__)


DEFAULT_AUTH_PIPELINE = (
    'third_party_auth.pipeline.parse_query_params',
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'third_party_auth.pipeline.associate_by_email_if_login_api',
    'social_core.pipeline.user.get_username',
    'third_party_auth.pipeline.set_pipeline_timeout',
    'sso_edx_tp.common_pipeline.check_active_status',
    'sso_edx_tp.pipeline.ensure_user_information',
    'sso_edx_tp.common_pipeline.try_to_set_password',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
    'sso_edx_tp.pipeline.apply_user_preferences',
    'third_party_auth.pipeline.set_logged_in_cookies',
    'third_party_auth.pipeline.login_analytics',
)


class TpBackend(BaseOAuth2):
    name = 'sso_tp-oauth2'
    ID_KEY = 'username'
    AUTHORIZATION_URL = '{}/oauth2/authorize'
    ACCESS_TOKEN_URL = '{}/oauth2/access_token'
    USER_DATA_URL = '{url}/oauth2/access_token/{access_token}/'
    DEFAULT_SCOPE = []
    REDIRECT_STATE = False
    REDIRECT_IS_HTTPS = getattr(settings, 'URL_PREFIX', 'https') == 'https'
    ACCESS_TOKEN_METHOD = 'POST'
    EXTRA_DATA = [
        ('refresh_token', 'refresh_token', True),
        ('expires_in', 'expires'),
    ]

    PIPELINE = DEFAULT_AUTH_PIPELINE
    skip_email_verification = True

    def __init__(self, *args, **kwargs):
        super(TpBackend, self).__init__(*args, **kwargs)
        self._current_site = get_site()
        # в предположении, что домен lms представляет lms_prfeix.domain.ru, а sso - sso.domain.ru
        base_domain = '.'.join(self._current_site.domain.split('.')[1:])
        self._sso_url = '{}://sso.{}'.format(getattr(settings, 'PLATFORM_SCHEME', 'https'), base_domain)

    def authorization_url(self):
        return self.AUTHORIZATION_URL.format(self._sso_url)

    def access_token_url(self):
        return self.ACCESS_TOKEN_URL.format(self._sso_url)

    def _get_info_from_request(self, request, post_param_name):
        if not request or request.method != 'POST':
            return None

        plp_api_key = getattr(settings, 'PLP_API_KEY', None)
        edx_api_key = getattr(settings, 'EDX_API_KEY', None)
        if not plp_api_key and not edx_api_key:
            return None

        plp_key = request.META.get('HTTP_X_PLP_API_KEY')
        edx_key = request.META.get('HTTP_X_EDX_API_KEY')
        if not plp_key and not edx_key:
            return None

        if (plp_api_key and plp_api_key == plp_key) or (edx_api_key and edx_api_key == edx_key):
            post_param_value = request.POST.get(post_param_name)
            if post_param_value:
                return post_param_value
        return None

    def setting(self, name, default=None):
        """Return setting value from strategy"""
        try:
            from third_party_auth.models import OAuth2ProviderConfig
        except ImportError:
            OAuth2ProviderConfig = None

        if OAuth2ProviderConfig is not None:
            site = self.strategy.request
            provider_config = OAuth2ProviderConfig.objects.filter(backend_name=self.name, site=self._current_site).order_by('-change_date').first()
            if not provider_config:
                raise Exception('Backend %s for domain %s not found' % (self.name, self._current_site.domain))
            if not provider_config.enabled:
                raise Exception("Can't fetch setting of a disabled backend.")
            try:
                return provider_config.get_setting(name)
            except KeyError:
                pass
        return super(TpBackend, self).setting(name, default=default)

    def auth_url(self):
        '''
        This function add "auth_entry" get attribute.
        "auth_entry" can be login or register, for correct redirect to login or register form
        on sso-provider.
        '''
        return '{}&auth_entry={}'.format(
            super(TpBackend, self).auth_url(),
            self.data.get('auth_entry', 'login')
        )

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes loging process, must return user instance"""
        self.strategy.session.setdefault('{}_state'.format(self.name),
                                         self.data.get('state'))
        next_url = getattr(settings, 'SOCIAL_NEXT_URL', '/home')
        self.strategy.session.setdefault('next', next_url)
        return super(TpBackend, self).auth_complete(*args, **kwargs)

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        """
        Hack for using in open edx our custom DEFAULT_AUTH_PIPELINE
        """
        self.strategy.session.setdefault('auth_entry', 'register')
        return super(TpBackend, self).pipeline(
            pipeline=self.PIPELINE, pipeline_index=pipeline_index, *args, **kwargs
        )

    def get_user_details(self, response):
        """ Return user details from SSO account. """
        return response

    def user_data(self, access_token, *args, **kwargs):
        """ Grab user profile information from SSO. """
        request = kwargs.get('request')
        user_info = self._get_info_from_request(request, 'user_info')
        if user_info:
            return json.loads(user_info)
        return self.get_json(
            '{}/users/me'.format(self._sso_url),
            params={'access_token': access_token},
            headers={'Authorization': 'Bearer {}'.format(access_token)},
        )

    def get_password_hash(self, access_token, *args, **kwargs):
        return self.get_json(
            '{}/users/get_hash'.format(settings.SSO_TP_URL),
            params={'access_token': access_token},
            headers={'Authorization': 'Bearer {}'.format(access_token)},
            method='POST',
        )

    def do_auth(self, access_token, *args, **kwargs):
        """Finish the auth process once the access_token was retrieved"""
        request = self.strategy.request
        data = self.user_data(access_token, request=request)
        data['access_token'] = access_token
        kwargs.update(data)
        response = kwargs.get('response') or {}
        response.update(data)
        kwargs.update({'response': response, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)

    def check_user_active_status(self, user):
        component = 'plp' if getattr(self, 'IS_PLP', False) else 'edx'
        return self.get_json(
            '{}/users/check-is-active/'.format(self._sso_url),
            data={'component': component, 'username': user.username},
            headers={'Authorization': 'Token {}'.format(settings.SSO_API_TOKEN)},
            method='POST',
        )


class TpBackendCMS(TpBackend):
    """
    Clone Backend for using in studio (cms).
    We need different auth backend for cms and lms
    """
    name = 'sso_tp_cms-oauth2'

    def get_user(self, user_id):
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            user = User.objects.get(id=user_id)
            return user
        except:
            return super(TpBackend, self).get_user(user_id)
