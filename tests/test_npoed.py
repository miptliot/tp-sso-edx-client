"""Integration tests for Tp providers."""
from third_party_auth.tests.specs import base
import mock


class TpOauth2IntegrationTest(base.Oauth2IntegrationTest):
    """Integration tests for provider.TpOauth2."""

    @classmethod
    def configure_tp_provider(cls, **kwargs):
        """ Update the settings for the Tp third party auth provider/backend """
        kwargs.setdefault("name", "SSO_TP")
        kwargs.setdefault("backend_name", "sso_tp-oauth2")
        kwargs.setdefault("icon_class", "fa-sing-in")
        kwargs.setdefault("key", "test-fake-key.apps.tp")
        kwargs.setdefault("secret", "opensesame")
        return cls.configure_oauth_provider(**kwargs)

    def setUp(self):
        super(TpOauth2IntegrationTest, self).setUp()
        self.provider = self.configure_tp_provider(
            enabled=True,
            key='tp_oauth2_key',
            secret='tp_oauth2_secret',
        )

    TOKEN_RESPONSE_DATA = {
        'access_token': 'access_token_value',
        'expires_in': 'expires_in_value',
        'id_token': 'id_token_value',
        'token_type': 'token_type_value',
    }
    USER_RESPONSE_DATA = {
        'email': 'email_value@example.com',
        'lastname': 'family_name_value',
        'firstname': 'given_name_value',
        'user_id': 'id_value',
        'username': 'name_value',
    }

    def get_username(self):
        return self.get_response_data().get('email').split('@')[0]

    def fake_user_data(self):
        return USER_RESPONSE_DATA

    def test_signin_fails_if_no_account_associated(self):
        _, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_LOGIN, redirect_uri='social:complete')

        strategy.request.backend.fake_user_data = mock.MagicMock(return_value=self.fake_user_data())
        print strategy.request.backend.fake_user_data
        strategy.request.backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
        self.create_user_models_for_existing_account(
            strategy, 'user@example.com', 'password', self.get_username(), skip_social_auth=True)

        self.assert_json_failure_response_is_missing_social_auth(student_views.login_user(strategy.request))
