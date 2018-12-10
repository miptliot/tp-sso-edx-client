import logging

from django.conf import settings

from social_core.utils import handle_http_errors
from social_core.backends.oauth import BaseOAuth2

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
    AUTHORIZATION_URL = '{}/oauth2/authorize'.format(settings.SSO_TP_URL)
    ACCESS_TOKEN_URL = '{}/oauth2/access_token'.format(settings.SSO_TP_URL)
    USER_DATA_URL = '{url}/oauth2/access_token/{access_token}/'
    DEFAULT_SCOPE = []
    REDIRECT_STATE = False
    ACCESS_TOKEN_METHOD = 'POST'

    PIPELINE = DEFAULT_AUTH_PIPELINE
    skip_email_verification = True

    def setting(self, name, default=None):
        """Return setting value from strategy"""
        try:
            from third_party_auth.models import OAuth2ProviderConfig
        except ImportError:
            OAuth2ProviderConfig = None

        if OAuth2ProviderConfig is not None:
            provider_config = OAuth2ProviderConfig.current(self.name)
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
        return self.get_json(
            '{}/users/me'.format(settings.SSO_TP_URL),
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
        data = self.user_data(access_token)
        data['access_token'] = access_token
        kwargs.update(data)
        kwargs.update({'response': data, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)

    def check_user_active_status(self, user):
        component = 'plp' if getattr(self, 'IS_PLP', False) else 'edx'
        return self.get_json(
            '{}/users/check-is-active/'.format(settings.SSO_TP_URL),
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