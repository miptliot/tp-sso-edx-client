# coding: utf-8

import re
import os.path
import requests

from django.conf import settings

try:
    from django.core.urlresolvers import reverse
except ImportError:
    from django.urls import reverse

from django.contrib.auth import REDIRECT_FIELD_NAME, logout, get_user_model
from django.shortcuts import redirect
try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    MiddlewareMixin = object

from .views import logout as sso_logout
from social_django.views import auth, NAMESPACE

try:
    from opaque_keys.edx.keys import CourseKey
    is_edx = True
except ImportError:
    msg = "Oh, it's not edx"
    is_edx = False
    CourseKey = None
    pass


def is_authenticated(user):
    if callable(user.is_authenticated):
        return user.is_authenticated()
    return user.is_authenticated


class SeamlessAuthorization(MiddlewareMixin):
    cookie_name = 'authenticated'

    def process_request(self, request):
        """
        Check multidomain cookie and if user is authenticated on sso, login it on edx
        """
        backend = settings.SSO_TP_BACKEND_NAME
        current_url = request.get_full_path()

        exluded_paths = ['/handler_noauth', '/xqueue', '/certificates']
        for exluded_path in exluded_paths:
            if exluded_path in current_url:
                return None

        special_xblock_urls = getattr(settings, 'SPECIAL_XBLOCK_URLS', [])

        for special_xblock_url in special_xblock_urls:
            if special_xblock_url in current_url:
                return None

        special_xblock_two_parts_urls = getattr(settings, 'SPECIAL_XBLOCK_TWO_PARTS_URLS', [])

        for part1, part2 in special_xblock_two_parts_urls:
            if part1 in current_url and part2 in current_url:
                return None

        # don't work for admin
        in_exclude_path = False
        for attr in ['SOCIAL_AUTH_EXCLUDE_URL_PATTERN', 'AUTOCOMPLETE_EXCLUDE_URL_PATTERN']:
            if hasattr(settings, attr):
                r = re.compile(getattr(settings, attr))
                if r.match(current_url):
                    in_exclude_path = True
                    break

        auth_cookie = request.COOKIES.get(self.cookie_name, '0').lower()
        auth_cookie_user = request.COOKIES.get('{}_user'.format(self.cookie_name))
        auth_cookie = (auth_cookie in ('1', 'true', 'ok'))
        continue_url = reverse('{0}:complete'.format(NAMESPACE),
                               args=(backend,))
        is_auth = is_authenticated(request.user)
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
        elif not auth_cookie and is_auth and not in_exclude_path:
            # Logout if user isn't logined on sso except for admin
            logout(request)

        if is_authenticated(request.user) and not request.user.is_active and is_edx:
            user = request.user
            user.is_active = True
            user.save()

        if is_authenticated(request.user):
            if not is_edx and not request.user.is_active:
                return sso_logout(request)
            elif is_edx:
                try:
                    # avoiding cache_toolbox.middleware.CacheBackedAuthenticationMiddleware
                    is_active = get_user_model().objects.get(username=request.user.username).is_active
                    if not is_active:
                        return sso_logout(request)
                except get_user_model().DoesNotExist:
                    return sso_logout(request)
        return None


class PLPRedirection(MiddlewareMixin):

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
        api_urls = ('certificates', 'api', 'user_api', 'notifier_api', 'update_example_certificate',
                    'update_certificate', 'request_certificate',)

        handle_local_urls = (
            'i18n', 'search', 'verify_student', 'certificates', 'jsi18n', 'course_modes',  '404', '500','i18n.js', 'js',
            'sso', 'wiki', 'notify', 'courses', 'xblock', 'change_setting', 'account', 'notification_prefs', 'admin',
            'survey', 'event', 'instructor_task_status', 'edinsights_service', 'openassessment', 'instructor_report',
            'media', 'sw.js'
        )

        handle_local_urls += auth_process_urls + api_urls

        if settings.DEBUG:
            debug_handle_local_urls = ('debug', settings.STATIC_URL, )
            handle_local_urls += debug_handle_local_urls
        
        handle_local_urls += (settings.MEDIA_URL.strip('/'), )

        if request.path == "/dashboard/" or request.path == "/dashboard":
            return redirect(os.path.join(settings.PLP_URL, 'my'))

        r_url = re.compile(r'^/courses/(.*)/about').match(current_url)
        es_url = re.compile(r'^/courses/(.*)/enroll_staff').match(current_url)
        if es_url:
            r_url = es_url
        if r_url and is_edx:
            course = CourseKey.from_string(r_url.groups()[0])
            # переход к конкретной сессии в plp
            return redirect(
                os.path.join(settings.PLP_URL, 'course', course.org, course.course) + '?session=%s' % course.run
            )

        is_courses_list_or_about_page = False
        r = re.compile(r'^/courses/%s/about' % settings.COURSE_ID_PATTERN)

        if r.match(current_url):
            is_courses_list_or_about_page = True

        if request.path == "/courses/" or request.path == "/courses":
            return redirect(os.path.join(settings.PLP_URL, 'course'))

        if request.path.startswith('/u/') or request.path.startswith("/account/settings"):
            return redirect(os.path.join(settings.PLP_URL, 'profile'))

        if start_url not in handle_local_urls or is_courses_list_or_about_page:
            if start_url.split('?')[0] not in handle_local_urls:
                plp_url = settings.PLP_URL
                if plp_url[-1] == '/':
                    plp_url = plp_url[:-1]
                return redirect("%s%s" % (plp_url, current_url))

        is_auth = is_authenticated(request.user)
        if not is_auth and start_url not in auth_process_urls and \
                start_url not in api_urls:
            request.session['force_auth'] = True


class CheckHonorAccepted(MiddlewareMixin):

    def process_request(self, request):
        current_url = request.get_full_path()
        course_pattern = re.compile(r'/course-v1:(\w+)\+(\w+)\+(\w+)/|$')
        course_pages = re.compile(r'courseware|discussion')
        check_course = re.search(course_pattern, current_url)
        check_pages = re.search(course_pages, current_url)

        if check_course and check_course.group() and check_pages and is_authenticated(request.user):
            university = check_course.group(1)
            course = check_course.group(2)
            session = check_course.group(3)
            course_id = 'course-v1:%s+%s+%s' % (university, course, session)
            if 'accepted_honor_codes' in request.session and isinstance(request.session['accepted_honor_codes'], dict):
                if request.session['accepted_honor_codes'].get(course_id):
                    return None
            request_url = os.path.join(settings.PLP_URL, 'api', 'user-accepted-honor-code')
            plp_api_key = settings.PLP_API_KEY
            r = requests.post(request_url,
                              {'course_id': course_id, 'username': request.user.username},
                              headers={'X-PLP-API-KEY': plp_api_key},
                              verify=False)
            accepted_honor_code = r.json()['honor']
            if not accepted_honor_code:
                return redirect(os.path.join(settings.PLP_URL, 'course/{}/{}?session={}'.format(university, course, session)))
            if 'accepted_honor_codes' in request.session and isinstance(request.session['accepted_honor_codes'], dict):
                request.session['accepted_honor_codes'][course_id] = True
            else:
                request.session['accepted_honor_codes'] = {course_id: True}
