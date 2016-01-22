import re
import os.path

from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME, logout
from django.shortcuts import redirect

from social.apps.django_app.views import auth, NAMESPACE
try:
    from opaque_keys.edx.keys import CourseKey
except:
    msg = "Oh, it's not edx"
    pass


class SeamlessAuthorization(object):
    cookie_name = 'authenticated'

    def process_request(self, request):
        """
        Check multidomain cookie and if user is authenticated on sso, login it on edx
        """
        backend = settings.SSO_NPOED_BACKEND_NAME
        current_url = request.get_full_path()

        # ITMO url hardcode
        special_xblock_url = 'courses/course-v1:ITMOUniversity+WEBDEV+fall_2015/xblock/block-v1:ITMOUniversity+WEBDEV+fall_2015+type'
        if special_xblock_url in current_url:
            return None

        # UrFU url hardcode
        special_urfu_xblock_url = 'courses/course-v1:urfu+METR+fall_2015/xblock/block-v1:urfu+METR+fall_2015+type'
        if special_urfu_xblock_url in current_url:
            return None

        # don't work for admin
        if hasattr(settings, 'SOCIAL_AUTH_EXCLUDE_URL_PATTERN'):
            r = re.compile(settings.SOCIAL_AUTH_EXCLUDE_URL_PATTERN)
            if r.match(current_url):
                return None

        auth_cookie = request.COOKIES.get(self.cookie_name, '0').lower()
        auth_cookie_user = request.COOKIES.get('{}_user'.format(self.cookie_name))
        auth_cookie = (auth_cookie in ('1', 'true', 'ok'))
        continue_url = reverse('{0}:complete'.format(NAMESPACE),
                               args=(backend,))
        is_auth = request.user.is_authenticated()
        # TODO: Need to uncomment after fix PLP
        is_same_user = (request.user.username == auth_cookie_user)

        # Check for infinity redirection loop
        is_continue = (continue_url in current_url)

        if (auth_cookie and not is_continue and (not is_auth or not is_same_user)) or \
                ('force_auth' in request.session and request.session.pop('force_auth')):
            query_dict = request.GET.copy()
            query_dict[REDIRECT_FIELD_NAME] = current_url
            query_dict['auth_entry'] = 'login'
            request.GET = query_dict
            logout(request)
            return auth(request, backend)
        elif not auth_cookie and is_auth:
            # Logout if user isn't logined on sso
            logout(request)

        return None


class PLPRedirection(object):

    def process_request(self, request):
        """
        Redirect to PLP for pages that have duplicated functionality on PLP
        """

        current_url = request.get_full_path()
        if current_url:
            start_url =  current_url.split('?')[0].split('/')[1]
        else:
            start_url = ''

        auth_process_urls = ('oauth2', 'auth', 'login_oauth_token', 'social-logout')
        api_urls = ('api', 'user_api', 'notifier_api', 'update_example_certificate',)

        handle_local_urls = (
            'i18n', 'search', 'verify_student', 'certificates', 'jsi18n', 'course_modes',  '404', '500','i18n.js',
            'wiki', 'notify', 'courses', 'xblock', 'change_setting', 'account', 'notification_prefs', 'admin',
            'survey', 'event', 'instructor_task_status', 'edinsights_service', 'openassessment', 'instructor_report',
        )

        handle_local_urls += auth_process_urls + api_urls

        if settings.DEBUG:
            debug_handle_local_urls = ('debug', settings.STATIC_URL, settings.MEDIA_URL)
            handle_local_urls += debug_handle_local_urls

        if request.path == "/dashboard/" or request.path == "/dashboard":
            return redirect(os.path.join(settings.PLP_URL, 'my'))

        r_url = re.compile(r'^/courses/(.*)/about').match(current_url)
        if r_url:
            course = CourseKey.from_string(r_url.groups()[0])
            return redirect(
                os.path.join(settings.PLP_URL, 'course', course.org, course.course)
            )

        is_courses_list_or_about_page = False
        r = re.compile(r'^/courses/%s/about' % settings.COURSE_ID_PATTERN)

        if r.match(current_url):
            is_courses_list_or_about_page = True

        if request.path == "/courses/" or request.path == "/courses":
            return redirect(os.path.join(settings.PLP_URL, 'course'))

        if request.path.startswith('/u/') or request.path == "/account/settings/" or request.path == "/account/settings":
            return redirect(os.path.join(settings.PLP_URL, 'profile'))

        if start_url not in handle_local_urls or is_courses_list_or_about_page:
            plp_url = settings.PLP_URL
            if plp_url[-1] == '/':
                plp_url = plp_url[:-1]
            return redirect("%s%s" % (plp_url, current_url))

        is_auth = request.user.is_authenticated()
        if not is_auth and start_url not in auth_process_urls and \
                start_url not in api_urls:
            request.session['force_auth'] = True
