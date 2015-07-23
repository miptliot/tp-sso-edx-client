import string  # pylint: disable-msg=deprecated-module
import json

from django.http import HttpResponseBadRequest, HttpResponse
from django.shortcuts import redirect
from django.utils.translation import ugettext as _
from social.exceptions import AuthException
from social.pipeline import partial

from student.cookies import set_logged_in_cookies
from student.views import create_account_with_params
import student

from logging import getLogger


logger = getLogger(__name__)

# The following are various possible values for the AUTH_ENTRY_KEY.
AUTH_ENTRY_LOGIN = 'login'
AUTH_ENTRY_REGISTER = 'register'
AUTH_ENTRY_ACCOUNT_SETTINGS = 'account_settings'

AUTH_ENTRY_LOGIN_2 = 'account_login'
AUTH_ENTRY_REGISTER_2 = 'account_register'

# Entry modes into the authentication process by a remote API call (as opposed to a browser session).
AUTH_ENTRY_LOGIN_API = 'login_api'
AUTH_ENTRY_REGISTER_API = 'register_api'


def is_api(auth_entry):
    """Returns whether the auth entry point is via an API call."""
    return (auth_entry == AUTH_ENTRY_LOGIN_API) or (auth_entry == AUTH_ENTRY_REGISTER_API)

AUTH_DISPATCH_URLS = {
    AUTH_ENTRY_LOGIN: '/login',
    AUTH_ENTRY_REGISTER: '/register',
    AUTH_ENTRY_ACCOUNT_SETTINGS: '/account/settings',

    # This is left-over from an A/B test
    # of the new combined login/registration page (ECOM-369)
    # We need to keep both the old and new entry points
    # until every session from before the test ended has expired.
    AUTH_ENTRY_LOGIN_2: '/account/login/',
    AUTH_ENTRY_REGISTER_2: '/account/register/',

}

_AUTH_ENTRY_CHOICES = frozenset([
    AUTH_ENTRY_LOGIN,
    AUTH_ENTRY_REGISTER,
    AUTH_ENTRY_ACCOUNT_SETTINGS,

    AUTH_ENTRY_LOGIN_2,
    AUTH_ENTRY_REGISTER_2,

    AUTH_ENTRY_LOGIN_API,
    AUTH_ENTRY_REGISTER_API,
])

_DEFAULT_RANDOM_PASSWORD_LENGTH = 12
_PASSWORD_CHARSET = string.letters + string.digits

class JsonResponse(HttpResponse):
    def __init__(self, data=None):
        super(JsonResponse, self).__init__(
            json.dumps(data), mimetype='application/json; charset=utf-8'
        )


@partial.partial
def ensure_user_information(strategy, auth_entry, backend=None, user=None, social=None,
                             allow_inactive_user=False, *args, **kwargs):
    """
    Ensure that we have the necessary information about a user (either an
    existing account or registration data) to proceed with the pipeline.
    """

    def dispatch_to_login():
        """Redirects to the login page."""
        return redirect(AUTH_DISPATCH_URLS[AUTH_ENTRY_LOGIN])

    def dispatch_to_register():
        """Redirects to the registration page."""

        request = strategy.request
        data = kwargs['response']
        data['terms_of_service'] = True
        data['honor_code'] = True
        data['password'] = 'edx'
        data['name'] = ' '.join([data['firstname'], data['lastname']])
        data['provider'] = backend.name

        if request.session.get('ExternalAuthMap'):
            del request.session['ExternalAuthMap']

        create_account_with_params(request, data)
        user = request.user
        user.is_active = True
        user.save()
        set_logged_in_cookies(request, JsonResponse({"success": True}))
        return redirect(AUTH_DISPATCH_URLS[AUTH_ENTRY_LOGIN])

    def should_force_account_creation():
        """ For some third party providers, we auto-create user accounts """
        current_provider = provider.Registry.get_from_pipeline(
            {'backend': backend.name, 'kwargs': kwargs}
        )
        return current_provider and current_provider.skip_email_verification

    if not user:
        if auth_entry in [AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API]:
            return HttpResponseBadRequest()
        elif auth_entry in [AUTH_ENTRY_LOGIN, AUTH_ENTRY_LOGIN_2]:
            return dispatch_to_register()
        elif auth_entry in [AUTH_ENTRY_REGISTER, AUTH_ENTRY_REGISTER_2]:
            return dispatch_to_register()
        elif auth_entry == AUTH_ENTRY_ACCOUNT_SETTINGS:
            raise AuthEntryError(backend, 'auth_entry is wrong. Settings requires a user.')
        else:
            raise AuthEntryError(backend, 'auth_entry invalid')

    if not user.is_active:
        if allow_inactive_user:
            pass
        elif social is not None:
            student.views.reactivation_email_for_user(user)
            raise NotActivatedException(backend, user.email)
