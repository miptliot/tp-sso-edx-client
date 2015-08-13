"""Integration tests for Npoed providers."""
import mock

from social import actions, exceptions
from social.apps.django_app import utils as social_utils
from social.apps.django_app import views as social_views

from third_party_auth.tests.specs import base
from third_party_auth import pipeline


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

    def test_canceling_authentication_redirects_to_login_when_auth_entry_login(self):
        self.assert_exception_redirect_looks_correct('/login', auth_entry=pipeline.AUTH_ENTRY_LOGIN)

    def test_canceling_authentication_redirects_to_register_when_auth_entry_register(self):
        self.assert_exception_redirect_looks_correct('/register', auth_entry=pipeline.AUTH_ENTRY_REGISTER)

    def test_canceling_authentication_redirects_to_login_when_auth_login_2(self):
        self.assert_exception_redirect_looks_correct('/account/login/', auth_entry=pipeline.AUTH_ENTRY_LOGIN_2)

    def test_canceling_authentication_redirects_to_login_when_auth_register_2(self):
        self.assert_exception_redirect_looks_correct('/account/register/', auth_entry=pipeline.AUTH_ENTRY_REGISTER_2)

    def test_canceling_authentication_redirects_to_account_settings_when_auth_entry_account_settings(self):
        self.assert_exception_redirect_looks_correct(
            '/account/settings', auth_entry=pipeline.AUTH_ENTRY_ACCOUNT_SETTINGS
        )

    def test_canceling_authentication_redirects_to_root_when_auth_entry_not_set(self):
        self.assert_exception_redirect_looks_correct('/')

    def test_full_pipeline_succeeds_for_linking_account(self):
        # First, create, the request and strategy that store pipeline state,
        # configure the backend, and mock out wire traffic.
        request, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_LOGIN, redirect_uri='social:complete')
        #request.backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
        #pipeline.analytics.track = mock.MagicMock()
        #request.user = self.create_user_models_for_existing_account(
        #    strategy, 'user@example.com', 'password', self.get_username(), skip_social_auth=True)

        # Instrument the pipeline to get to the dashboard with the full
        # expected state.
        self.client.get(
            pipeline.get_login_url(self.provider.provider_id, pipeline.AUTH_ENTRY_LOGIN))
        #actions.do_complete(request.backend, social_views._do_login)  # pylint: disable=protected-access

        #mako_middleware_process_request(strategy.request)
        #student_views.signin_user(strategy.request)
        #student_views.login_user(strategy.request)
        #actions.do_complete(request.backend, social_views._do_login)  # pylint: disable=protected-access

        # First we expect that we're in the unlinked state, and that there
        # really is no association in the backend.
        #self.assert_account_settings_context_looks_correct(account_settings_context(request), request.user, linked=False)
        #self.assert_social_auth_does_not_exist_for_user(request.user, strategy)

        # We should be redirected back to the complete page, setting
        # the "logged in" cookie for the marketing site.
        #self.assert_logged_in_cookie_redirect(actions.do_complete(
        #    request.backend, social_views._do_login, request.user, None,  # pylint: disable=protected-access
        #    redirect_field_name=auth.REDIRECT_FIELD_NAME
        #))

        # Set the cookie and try again
        #self.set_logged_in_cookies(request)

        # Fire off the auth pipeline to link.
        #self.assert_redirect_to_dashboard_looks_correct(actions.do_complete(
        #    request.backend, social_views._do_login, request.user, None,  # pylint: disable=protected-access
        #    redirect_field_name=auth.REDIRECT_FIELD_NAME))

        # Now we expect to be in the linked state, with a backend entry.
        #self.assert_social_auth_exists_for_user(request.user, strategy)
        #self.assert_account_settings_context_looks_correct(account_settings_context(request), request.user, linked=True)

    def test_full_pipeline_succeeds_for_unlinking_account(self):
        # First, create, the request and strategy that store pipeline state,
        # configure the backend, and mock out wire traffic.
        request, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_LOGIN, redirect_uri='social:complete')
        #request.backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
        #user = self.create_user_models_for_existing_account(
        #    strategy, 'user@example.com', 'password', self.get_username())
        #self.assert_social_auth_exists_for_user(user, strategy)

        # We're already logged in, so simulate that the cookie is set correctly
        #self.set_logged_in_cookies(request)

        # Instrument the pipeline to get to the dashboard with the full
        # expected state.
        self.client.get(
            pipeline.get_login_url(self.provider.provider_id, pipeline.AUTH_ENTRY_LOGIN))
        #actions.do_complete(request.backend, social_views._do_login)  # pylint: disable=protected-access

        #mako_middleware_process_request(strategy.request)
        #student_views.signin_user(strategy.request)
        #student_views.login_user(strategy.request)
        #actions.do_complete(request.backend, social_views._do_login, user=user)  # pylint: disable=protected-access

        # First we expect that we're in the linked state, with a backend entry.
        #self.assert_account_settings_context_looks_correct(account_settings_context(request), user, linked=True)
        #self.assert_social_auth_exists_for_user(request.user, strategy)

        ## Fire off the disconnect pipeline to unlink.
        #self.assert_redirect_to_dashboard_looks_correct(actions.do_disconnect(
        #    request.backend, request.user, None, redirect_field_name=auth.REDIRECT_FIELD_NAME))

        ## Now we expect to be in the unlinked state, with no backend entry.
        #self.assert_account_settings_context_looks_correct(account_settings_context(request), user, linked=False)
        #self.assert_social_auth_does_not_exist_for_user(user, strategy)

    def test_linking_already_associated_account_raises_auth_already_associated(self):
        # This is of a piece with
        # test_already_associated_exception_populates_dashboard_with_error. It
        # verifies the exception gets raised when we expect; the latter test
        # covers exception handling.
        email = 'user@example.com'
        password = 'password'
        username = self.get_username()
        _, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_LOGIN, redirect_uri='social:complete')
        backend = strategy.request.backend
        #backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
        #linked_user = self.create_user_models_for_existing_account(strategy, email, password, username)
        #unlinked_user = social_utils.Storage.user.create_user(
        #    email='other_' + email, password=password, username='other_' + username)

        #self.assert_social_auth_exists_for_user(linked_user, strategy)
        #self.assert_social_auth_does_not_exist_for_user(unlinked_user, strategy)

        #with self.assertRaises(exceptions.AuthAlreadyAssociated):
        #    # pylint: disable=protected-access
        #    actions.do_complete(backend, social_views._do_login, user=unlinked_user)

    def test_already_associated_exception_populates_dashboard_with_error(self):
        # Instrument the pipeline with an exception. We test that the
        # exception is raised correctly separately, so it's ok that we're
        # raising it artificially here. This makes the linked=True artificial
        # in the final assert because in practice the account would be
        # unlinked, but getting that behavior is cumbersome here and already
        # covered in other tests. Using linked=True does, however, let us test
        # that the duplicate error has no effect on the state of the controls.
        request, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_LOGIN, redirect_uri='social:complete')
        #strategy.request.backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
        #user = self.create_user_models_for_existing_account(
        #    strategy, 'user@example.com', 'password', self.get_username())
        #self.assert_social_auth_exists_for_user(user, strategy)

        #self.client.get('/login')
        #self.client.get(pipeline.get_login_url(self.provider.provider_id, pipeline.AUTH_ENTRY_LOGIN))
        #actions.do_complete(request.backend, social_views._do_login)  # pylint: disable=protected-access

        #mako_middleware_process_request(strategy.request)
        #student_views.signin_user(strategy.request)
        #student_views.login_user(strategy.request)
        #actions.do_complete(request.backend, social_views._do_login, user=user)  # pylint: disable=protected-access

        # Monkey-patch storage for messaging; pylint: disable=protected-access
        #request._messages = fallback.FallbackStorage(request)
        #middleware.ExceptionMiddleware().process_exception(
        #    request,
        #    exceptions.AuthAlreadyAssociated(self.provider.backend_name, 'account is already in use.'))

        #self.assert_account_settings_context_looks_correct(
        #    account_settings_context(request), user, duplicate=True, linked=True)

    def test_full_pipeline_succeeds_for_signing_in_to_existing_active_account(self):
        # First, create, the request and strategy that store pipeline state,
        # configure the backend, and mock out wire traffic.
        request, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_LOGIN, redirect_uri='social:complete')
        #strategy.request.backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
        #pipeline.analytics.track = mock.MagicMock()
        #user = self.create_user_models_for_existing_account(
        #    strategy, 'user@example.com', 'password', self.get_username())
        #self.assert_social_auth_exists_for_user(user, strategy)
        #self.assertTrue(user.is_active)

        ## Begin! Ensure that the login form contains expected controls before
        ## the user starts the pipeline.
        #self.assert_login_response_before_pipeline_looks_correct(self.client.get('/login'))

        ## The pipeline starts by a user GETting /auth/login/<provider>.
        ## Synthesize that request and check that it redirects to the correct
        ## provider page.
        #self.assert_redirect_to_provider_looks_correct(self.client.get(
        #    pipeline.get_login_url(self.provider.provider_id, pipeline.AUTH_ENTRY_LOGIN)))

        ## Next, the provider makes a request against /auth/complete/<provider>
        ## to resume the pipeline.
        ## pylint: disable=protected-access
        #self.assert_redirect_to_login_looks_correct(actions.do_complete(request.backend, social_views._do_login))

        #mako_middleware_process_request(strategy.request)
        ## At this point we know the pipeline has resumed correctly. Next we
        ## fire off the view that displays the login form and posts it via JS.
        #self.assert_login_response_in_pipeline_looks_correct(student_views.signin_user(strategy.request))

        ## Next, we invoke the view that handles the POST, and expect it
        ## redirects to /auth/complete. In the browser ajax handlers will
        ## redirect the user to the dashboard; we invoke it manually here.
        #self.assert_json_success_response_looks_correct(student_views.login_user(strategy.request))

        ## We should be redirected back to the complete page, setting
        ## the "logged in" cookie for the marketing site.
        #self.assert_logged_in_cookie_redirect(actions.do_complete(
        #    request.backend, social_views._do_login, request.user, None,  # pylint: disable=protected-access
        #    redirect_field_name=auth.REDIRECT_FIELD_NAME
        #))

        ## Set the cookie and try again
        #self.set_logged_in_cookies(request)

        #self.assert_redirect_to_dashboard_looks_correct(
        #    actions.do_complete(request.backend, social_views._do_login, user=user))
        #self.assert_account_settings_context_looks_correct(account_settings_context(request), user)

    def test_signin_fails_if_account_not_active(self):
        _, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_LOGIN, redirect_uri='social:complete')
    #    strategy.request.backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
    #    user = self.create_user_models_for_existing_account(strategy, 'user@example.com', 'password', self.get_username())

    #    user.is_active = False
    #    user.save()

    #    mako_middleware_process_request(strategy.request)
    #    self.assert_json_failure_response_is_inactive_account(student_views.login_user(strategy.request))

    def test_signin_fails_if_no_account_associated(self):
        _, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_LOGIN, redirect_uri='social:complete')
    #    strategy.request.backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
    #    self.create_user_models_for_existing_account(
    #        strategy, 'user@example.com', 'password', self.get_username(), skip_social_auth=True)

    #    self.assert_json_failure_response_is_missing_social_auth(student_views.login_user(strategy.request))

    def test_first_party_auth_trumps_third_party_auth_but_is_invalid_when_only_email_in_request(self):
        pass
        #self.assert_first_party_auth_trumps_third_party_auth(email='user@example.com')

    def test_first_party_auth_trumps_third_party_auth_but_is_invalid_when_only_password_in_request(self):
        pass
        #self.assert_first_party_auth_trumps_third_party_auth(password='password')

    def test_first_party_auth_trumps_third_party_auth_and_fails_when_credentials_bad(self):
        pass
        #self.assert_first_party_auth_trumps_third_party_auth(
        #    email='user@example.com', password='password', success=False)

    def test_first_party_auth_trumps_third_party_auth_and_succeeds_when_credentials_good(self):
        pass
        #self.assert_first_party_auth_trumps_third_party_auth(
        #    email='user@example.com', password='password', success=True)

    def test_full_pipeline_succeeds_registering_new_account(self):
        # First, create, the request and strategy that store pipeline state.
        # Mock out wire traffic.
        request, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_REGISTER, redirect_uri='social:complete')
        #strategy.request.backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))

        ## Begin! Grab the registration page and check the login control on it.
        #self.assert_register_response_before_pipeline_looks_correct(self.client.get('/register'))

        ## The pipeline starts by a user GETting /auth/login/<provider>.
        ## Synthesize that request and check that it redirects to the correct
        ## provider page.
        #self.assert_redirect_to_provider_looks_correct(self.client.get(
        #    pipeline.get_login_url(self.provider.provider_id, pipeline.AUTH_ENTRY_LOGIN)))

        ## Next, the provider makes a request against /auth/complete/<provider>.
        ## pylint: disable=protected-access
        #self.assert_redirect_to_register_looks_correct(actions.do_complete(request.backend, social_views._do_login))

        #mako_middleware_process_request(strategy.request)
        ## At this point we know the pipeline has resumed correctly. Next we
        ## fire off the view that displays the registration form.
        #self.assert_register_response_in_pipeline_looks_correct(
        #    student_views.register_user(strategy.request), pipeline.get(request)['kwargs'])

        ## Next, we invoke the view that handles the POST. Not all providers
        ## supply email. Manually add it as the user would have to; this
        ## also serves as a test of overriding provider values. Always provide a
        ## password for us to check that we override it properly.
        #overridden_password = strategy.request.POST.get('password')
        #email = 'new@example.com'

        #if not strategy.request.POST.get('email'):
        #    strategy.request.POST = self.get_registration_post_vars({'email': email})

        ## The user must not exist yet...
        #with self.assertRaises(auth_models.User.DoesNotExist):
        #    self.get_user_by_email(strategy, email)

        ## ...but when we invoke create_account the existing edX view will make
        ## it, but not social auths. The pipeline creates those later.
        #self.assert_json_success_response_looks_correct(student_views.create_account(strategy.request))
        ## We've overridden the user's password, so authenticate() with the old
        ## value won't work:
        #created_user = self.get_user_by_email(strategy, email)
        #self.assert_password_overridden_by_pipeline(overridden_password, created_user.username)

        ## At this point the user object exists, but there is no associated
        ## social auth.
        #self.assert_social_auth_does_not_exist_for_user(created_user, strategy)

        ## We should be redirected back to the complete page, setting
        # the "logged in" cookie for the marketing site.
        #self.assert_logged_in_cookie_redirect(actions.do_complete(
        #    request.backend, social_views._do_login, request.user, None,  # pylint: disable=protected-access
        #    redirect_field_name=auth.REDIRECT_FIELD_NAME
        #))

        ## Set the cookie and try again
        #self.set_logged_in_cookies(request)
        #self.assert_redirect_to_dashboard_looks_correct(
        #    actions.do_complete(strategy.request.backend, social_views._do_login, user=created_user))
        ## Now the user has been redirected to the dashboard. Their third party account should now be linked.
        #self.assert_social_auth_exists_for_user(created_user, strategy)
        #self.assert_account_settings_context_looks_correct(account_settings_context(request), created_user, linked=True)

    def test_new_account_registration_assigns_distinct_username_on_collision(self):
        original_username = self.get_username()
        request, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_REGISTER, redirect_uri='social:complete')

        # Create a colliding username in the backend, then proceed with
        # assignment via pipeline to make sure a distinct username is created.
        strategy.storage.user.create_user(username=self.get_username(), email='user@email.com', password='password')
        backend = strategy.request.backend
        #backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
        ## pylint: disable=protected-access
        #self.assert_redirect_to_register_looks_correct(actions.do_complete(backend, social_views._do_login))
        #distinct_username = pipeline.get(request)['kwargs']['username']
        #self.assertNotEqual(original_username, distinct_username)

    def test_new_account_registration_fails_if_email_exists(self):
        request, strategy = self.get_request_and_strategy(
            auth_entry=pipeline.AUTH_ENTRY_REGISTER, redirect_uri='social:complete')
        backend = strategy.request.backend
        #backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
        ## pylint: disable=protected-access
        #self.assert_redirect_to_register_looks_correct(actions.do_complete(backend, social_views._do_login))

        #mako_middleware_process_request(strategy.request)
        #self.assert_register_response_in_pipeline_looks_correct(
        #    student_views.register_user(strategy.request), pipeline.get(request)['kwargs'])
        #strategy.request.POST = self.get_registration_post_vars()
        ## Create twice: once successfully, and once causing a collision.
        #student_views.create_account(strategy.request)
        #self.assert_json_failure_response_is_username_collision(student_views.create_account(strategy.request))

    def test_pipeline_raises_auth_entry_error_if_auth_entry_invalid(self):
        auth_entry = 'invalid'
        self.assertNotIn(auth_entry, pipeline._AUTH_ENTRY_CHOICES)  # pylint: disable=protected-access

        _, strategy = self.get_request_and_strategy(auth_entry=auth_entry, redirect_uri='social:complete')

        #with self.assertRaises(pipeline.AuthEntryError):
        #    strategy.request.backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))

    def test_pipeline_raises_auth_entry_error_if_auth_entry_missing(self):
        _, strategy = self.get_request_and_strategy(auth_entry=None, redirect_uri='social:complete')

        #with self.assertRaises(pipeline.AuthEntryError):
        #    strategy.request.backend.auth_complete = mock.MagicMock(return_value=self.fake_auth_complete(strategy))
