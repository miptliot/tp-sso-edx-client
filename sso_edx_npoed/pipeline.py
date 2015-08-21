import string  # pylint: disable-msg=deprecated-module
import json
import logging

from django.http import HttpResponseBadRequest, HttpResponse
from django.shortcuts import redirect
from django.utils.translation import ugettext as _
from django.contrib.auth.models import User

from social.exceptions import AuthException
from social.pipeline import partial

#from student.cookies import set_logged_in_cookies
from student.views import create_account_with_params

from student.roles import (
    CourseInstructorRole, CourseStaffRole, GlobalStaff, OrgStaffRole,
    UserBasedRole, CourseCreatorRole, CourseBetaTesterRole, OrgInstructorRole
)

from openedx.core.djangoapps.content.course_structures.models import CourseStructure
import student


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


def set_roles_for_edx_users(user, permissions, strategy):
    '''
    This function is specific functional for open-edx platform.
    It create roles for edx users from sso permissions.
    '''

    message = 'For User: {}, object_type {} and object_id {} there is not matched Role for Permission set: {}'
    logging.basicConfig(filename=strategy.get_setting('LOGGING_EDX_ROLES_URL'), level=logging.DEBUG)

    global_perm = set([
            'Read', 'Update', 'Delete', 'Publication', 'Enroll',
            'Manage(permissions)'
        ])
    staff_perm = set(['Read', 'Update', 'Delete', 'Publication', 'Enroll'])
    tester_perm = set(['Read', 'Enroll'])
    for role in permissions:
        if role['obj_type'] == '*':
            if '*' in role['obj_perm'] or global_perm.issubset(set(role['obj_perm'])):
                GlobalStaff().add_users(user)
                if len(global_perm) < len(role['obj_perm']):
                    _log = message.format(
                        user.id, role['obj_type'], role['obj_id'],
                        str(role['obj_perm'])
                    )
            elif 'Create' in role['obj_perm']:
                CourseCreatorRole().add_users(user)
            else:
                _log = message.format(
                    user.id, role['obj_type'], role['obj_id'],
                    str(role['obj_perm'])
                )
        elif role['obj_type'] == 'edx org':
            if '*' in role['obj_perm'] or global_perm.issubset(set(role['obj_perm'])):
                OrgInstructorRole(role['obj_id']).add_users(user)
                if len(global_perm) < len(role['obj_perm']):
                    _log = message.format(
                        user.id, role['obj_type'], role['obj_id'],
                        str(role['obj_perm'])
                    )
            elif staff_perm.issubset(set(role['obj_perm'])):
                OrgStaffRole(role['obj_id']).add_users(user)
                if len(staff_perm) < len(role['obj_perm']):
                    _log = message.format(
                        user.id, role['obj_type'], role['obj_id'],
                        str(role['obj_perm'])
                    )
            else:
                _log = message.format(
                    user.id, role['obj_type'], role['obj_id'],
                    str(role['obj_perm'])
                )
        elif role['obj_type'] == 'edx course':
            if '*' in role['obj_perm'] or global_perm.issubset(set(role['obj_perm'])):
                CourseInstructorRole(role['obj_id']).add_users(user)
                if len(global_perm) < len(role['obj_perm']):
                    _log = message.format(
                        user.id, role['obj_type'], role['obj_id'],
                        str(role['obj_perm'])
                    )
            elif staff_perm.issubset(set(role['obj_perm'])):
                CourseStaffRole(role['obj_id']).add_users(user)
                if len(staff_perm) < len(role['obj_perm']):
                    _log = message.format(
                        user.id, role['obj_type'], role['obj_id'],
                        str(role['obj_perm'])
                    )
            elif tester_perm.issubset(set(role['obj_perm'])):
                CourseBetaTesterRole(role['obj_id']).add_users(user)
                if len(tester_perm) < len(role['obj_perm']):
                    _log = message.format(
                        user.id, role['obj_type'], role['obj_id'],
                        str(role['obj_perm'])
                    )
            else:
                _log = message.format(
                    user.id, role['obj_type'], role['obj_id'],
                    str(role['obj_perm'])
                )
        elif role['obj_type'] == 'edx course run':
            if '*' in role['obj_perm'] or global_perm.issubset(set(role['obj_perm'])):
                CourseInstructorRole(role['obj_id']).add_users(user)
                if len(global_perm) < len(role['obj_perm']):
                    _log = message.format(
                        user.id, role['obj_type'], role['obj_id'],
                        str(role['obj_perm'])
                    )
            elif staff_perm.issubset(set(role['obj_perm'])):
                CourseStaffRole(role['obj_id']).add_users(user)
                if len(staff_perm) < len(role['obj_perm']):
                    _log = message.format(
                        user.id, role['obj_type'], role['obj_id'],
                        str(role['obj_perm'])
                    )
            elif tester_perm.issubset(set(role['obj_perm'])):
                CourseBetaTesterRole(role['obj_id']).add_users(user)
                if len(tester_perm) < len(role['obj_perm']):
                    _log = message.format(
                        user.id, role['obj_type'], role['obj_id'],
                        str(role['obj_perm'])
                    )
            else:
                _log = message.format(
                    user.id, role['obj_type'], role['obj_id'],
                    str(role['obj_perm'])
                )

        logging.warning(_log)

        # elif role['obj_type'] == 'edx course enrollment':
        #     if '*' in role['obj_perm']:
        #         ''


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

    response = {}

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

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            create_account_with_params(request, data)
            user = request.user
            user.is_active = True
            user.save()

        return {'user': user}

    if not user:
        if auth_entry in [AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API]:
            return HttpResponseBadRequest()
        elif auth_entry in [AUTH_ENTRY_LOGIN, AUTH_ENTRY_LOGIN_2]:
            response = dispatch_to_register()
        elif auth_entry in [AUTH_ENTRY_REGISTER, AUTH_ENTRY_REGISTER_2]:
            response = dispatch_to_register()
        elif auth_entry == AUTH_ENTRY_ACCOUNT_SETTINGS:
            raise AuthEntryError(backend, 'auth_entry is wrong. Settings requires a user.')
        else:
            raise AuthEntryError(backend, 'auth_entry invalid')

    user = response.get('user')
    if user and not user.is_active:
        if allow_inactive_user:
            pass
        elif social is not None:
            student.views.reactivation_email_for_user(user)
            raise NotActivatedException(backend, user.email)

    # add roles for User
    permissions = kwargs.get('response', {}).get('permissions')
    if permissions and user:
        set_roles_for_edx_users(user, permissions, strategy)

    return response
