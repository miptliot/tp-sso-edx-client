import re

from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME, logout

from social.apps.django_app.views import auth, NAMESPACE


class SeamlessAuthorization(object):
    cookie_name = 'authenticated'

    def process_request(self, request):
        backend = settings.SSO_NPOED_BACKEND_NAME
        current_url = request.get_full_path()

        if hasattr(settings, 'SOCIAL_AUTH_EXCLUDE_URL_PATTERN'):
            r = re.compile(settings.SOCIAL_AUTH_EXCLUDE_URL_PATTERN)
            if r.match(current_url):
                return None

        auth_cookie = request.COOKIES.get(self.cookie_name, '0').lower()
        auth_cookie = (auth_cookie in ('1', 'true', 'ok'))
        continue_url = reverse('{0}:complete'.format(NAMESPACE),
                               args=(backend,))
        is_auth = request.user.is_authenticated()

        is_continue = (continue_url in current_url)

        if auth_cookie and not is_continue and not is_auth:
            query_dict = request.GET.copy()
            query_dict[REDIRECT_FIELD_NAME] = current_url
            query_dict['auth_entry'] = 'login'
            request.GET = query_dict
            return auth(request, backend)
        elif not auth_cookie and is_auth:
            logout(request)

        return None
