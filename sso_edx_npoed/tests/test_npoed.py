"""Integration tests for Npoed providers."""
from third_party_auth.tests.specs import base


class NpoedOauth2IntegrationTest(base.Oauth2IntegrationTest):
    """Integration tests for provider.NpoedOauth2."""

    @classmethod
    def configure_npoed_provider(cls, **kwargs):
        """ Update the settings for the Npoed third party auth provider/backend """
        kwargs.setdefault("name", "Npoed")
        kwargs.setdefault("backend_name", "sso_npoed-oauth2")
        kwargs.setdefault("icon_class", "fa-sing-in")
        kwargs.setdefault("key", "test-fake-key.apps.npoed")
        kwargs.setdefault("secret", "opensesame")
        return cls.configure_oauth_provider(**kwargs)

    def setUp(self):
        super(NpoedOauth2IntegrationTest, self).setUp()
        self.provider = self.configure_npoed_provider(
            enabled=True,
            key='npoed_oauth2_key',
            secret='npoed_oauth2_secret',
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
