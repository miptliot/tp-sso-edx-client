import logging

from django.conf import settings
from social.backends.oauth import BaseOAuth2

log = logging.getLogger(__name__)


SOCIAL_AUTH_PIPELINE = (
    'third_party_auth.pipeline.parse_query_params',
    'social.pipeline.social_auth.social_details',
    'social.pipeline.social_auth.social_uid',
    'social.pipeline.social_auth.auth_allowed',
    'social.pipeline.social_auth.social_user',
    'third_party_auth.pipeline.associate_by_email_if_login_api',
    'social.pipeline.user.get_username',
    'third_party_auth.pipeline.set_pipeline_timeout',
    'sso_edx_npoed.pipeline.ensure_user_information',
    'social.pipeline.user.create_user',
    'social.pipeline.social_auth.associate_user',
    'social.pipeline.social_auth.load_extra_data',
    'social.pipeline.user.user_details',
    'third_party_auth.pipeline.set_logged_in_cookies',
    'third_party_auth.pipeline.login_analytics',
)

class NpoedBackend(BaseOAuth2):

    name = 'sso_npoed-oauth2'
    ID_KEY = 'user_id'
    AUTHORIZATION_URL = 'http://sso.rnoep.raccoongang.com/oauth2/authorize'
    ACCESS_TOKEN_URL = 'http://sso.rnoep.raccoongang.com/oauth2/access_token'
    DEFAULT_SCOPE = []
    REDIRECT_STATE = False
    ACCESS_TOKEN_METHOD = 'POST'

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):

        pipeline = SOCIAL_AUTH_PIPELINE

        out = self.run_pipeline(pipeline, pipeline_index, *args, **kwargs)
        if not isinstance(out, dict):
            return out
        user = out.get('user')
        if user:
            user.social_user = out.get('social')
            user.is_new = out.get('is_new')
        return user

    def get_user_details(self, response):
        """ Return user details from MIPT account. """
        return response

    def user_data(self, access_token, *args, **kwargs):
        """ Grab user profile information from MIPT. """
        return self.get_json(
            'http://sso.rnoep.raccoongang.com/oauth2/access_token/%s/' % access_token,
            params={'access_token': access_token}
        )

    def do_auth(self, access_token, *args, **kwargs):
        """Finish the auth process once the access_token was retrieved"""
        data = self.user_data(access_token)
        data['access_token'] = access_token
        kwargs.update(data)
        kwargs.update({'response': data, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)
