# coding: utf8

import string  # pylint: disable-msg=deprecated-module
import json
import logging

from django.http import HttpResponseBadRequest, HttpResponse
from django.contrib.auth.models import User

from openedx.core.djangoapps.user_api.models import UserPreference
from student.views import create_account_with_params, reactivation_email_for_user
from student.models import UserProfile, CourseAccessRole, create_comments_service_user, CourseEnrollment
from student.roles import (
    CourseInstructorRole, CourseStaffRole, GlobalStaff, OrgStaffRole,
    UserBasedRole, CourseCreatorRole, CourseBetaTesterRole, OrgInstructorRole,
    LibraryUserRole, OrgLibraryUserRole
)
from third_party_auth.pipeline import (
    make_random_password, AuthEntryError
)
from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError
from collections import OrderedDict
from .roles import BaseUserRole

log = logging.getLogger(__name__)

# The following are various possible values for the AUTH_ENTRY_KEY.
AUTH_ENTRY_LOGIN = 'login'
AUTH_ENTRY_REGISTER = 'register'
AUTH_ENTRY_ACCOUNT_SETTINGS = 'account_settings'

AUTH_ENTRY_LOGIN_2 = 'account_login'
AUTH_ENTRY_REGISTER_2 = 'account_register'

# Entry modes into the authentication process by a remote API call (as opposed to a browser session).
AUTH_ENTRY_LOGIN_API = 'login_api'
AUTH_ENTRY_REGISTER_API = 'register_api'

# Values from sso that should be checked and pushed at auth
PREFERENCE_KEY_LIST = ("time_zone",)


class UserRole(BaseUserRole):
    @classmethod
    def get_role_by_type(cls, role):
        role_id = int(role['role']['type'])

        try:
            if role_id in (cls.TYPE_SUPERADMIN, cls.TYPE_GLOBAL_ADMIN):
                return GlobalStaff, {}, True
            elif role_id == cls.TYPE_ORG_ADMIN:
                return OrgStaffRole, OrderedDict([('org', role['obj_id'])]), False
            elif role_id in (cls.TYPE_COURSERUN_AUTHOR, cls.TYPE_COURSE_AUTHOR):
                course_key = CourseKey.from_string(role['obj_id'])
                return CourseInstructorRole, OrderedDict([('course_id', course_key)]), False
            elif role_id == cls.TYPE_BETA_TESTER:
                course_key = CourseKey.from_string(role['obj_id'])
                return CourseBetaTesterRole, OrderedDict([('course_id', course_key)]), False
        except InvalidKeyError:
            logging.warning('Can\'t convert {} to the course key'.format(str(role['obj_id'])))
        return None, {}, False


def is_api(auth_entry):
    """Returns whether the auth entry point is via an API call."""
    return (auth_entry == AUTH_ENTRY_LOGIN_API) or (auth_entry == AUTH_ENTRY_REGISTER_API)


def _update_role_data(role):
    orgs = ['urfu', 'misis', 'spbstu', 'spbu', 'msu', 'tgu']
    course_id_prefix = 'course-v1:'

    obj_id = role['obj_id'].lower()
    if obj_id in orgs:
        role['obj_id'] = obj_id
    if course_id_prefix in role['obj_id']:
        org_id = role['obj_id'].split(":")[1].split("+")[0]
        if org_id.lower() != org_id and org_id.lower() in orgs:
            obj_id_parts = role['obj_id'].split(":")[1].split("+")
            role['obj_id'] = course_id_prefix + org_id.lower() + '+' + obj_id_parts[1] + '+' + obj_id_parts[2]
    return role


def set_roles_for_edx_users(user, permissions, strategy):
    """
    This function is specific functional for open-edx platform.
    It create roles for edx users from sso permissions.
    """
    was_set_global_staff = False
    role_ids = set(user.courseaccessrole_set.values_list('id', flat=True))
    new_role_ids = []

    for role in permissions:

        if role['obj_id']:
            role = _update_role_data(role)

        role_class, role_kwargs, is_super_user = UserRole.get_role_by_type(role)

        if is_super_user:
            if not was_set_global_staff:
                GlobalStaff().add_users(user)
                was_set_global_staff = True
        else:
            if role_class is not None:
                role_args = role_kwargs.values()
                role_obj = role_class(*role_args)

                if not role_obj.has_user(user):
                    role_obj.add_users(user)
                    if role_class is CourseBetaTesterRole and not CourseEnrollment.objects.\
                            filter(is_active=True, user=user, course_id=role_kwargs['course_id']).exists():
                        enrollment = CourseEnrollment.get_or_create_enrollment(user, role_kwargs['course_id'])
                        enrollment.update_enrollment(is_active=True, mode='honor')
                car = CourseAccessRole.objects.get(user=user, role=role_obj._role_name, **role_kwargs)
                new_role_ids.append(car.id)
            else:
                logging.warning('For User: {}, role {}, object_type {} and object_id {} there is not matched '
                                'Role for Permission set: {}'.format(user.id, str(role['role']), role['obj_type'],
                                                                     role['obj_id'], str(role['obj_perm'])))

    if (not was_set_global_staff) and GlobalStaff().has_user(user) and user.id != 1:
        GlobalStaff().remove_users(user)

    remove_roles = role_ids - set(new_role_ids)
    if remove_roles:
        entries = CourseAccessRole.objects.exclude(
            course_id__icontains='library').filter(id__in=list(remove_roles))
        entries.delete()


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


def ensure_user_information(
    strategy, auth_entry, backend=None, user=None, social=None,
    allow_inactive_user=False, *args, **kwargs):
    """
    Ensure that we have the necessary information about a user (either an
    existing account or registration data) to proceed with the pipeline.
    """

    response = {}
    data = kwargs['response']

    def dispatch_to_register():
        """Force user creation on login or register"""

        request = strategy.request
        data['terms_of_service'] = 'true'
        data['honor_code'] = 'true'
        data['password'] = make_random_password()
        # force name creation if it is empty in sso-profile
        data['name'] = ' '.join([data.get('firstname', ''),
                                 data.get('lastname', '')]).strip() or data['username']
        data['provider'] = backend.name

        if request.session.get('ExternalAuthMap'):
            del request.session['ExternalAuthMap']

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            _provider = data.pop('provider')
            user = create_account_with_params(request, data)
            data['provider'] = _provider
            user.first_name = data.get('firstname')
            user.last_name = data.get('lastname')
            user.is_active = True
            user.save()
            create_comments_service_user(user)

            return {}
        return {'user': user}

    if not user:
        if auth_entry in [AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API]:
            return HttpResponseBadRequest()
        elif auth_entry in [AUTH_ENTRY_LOGIN, AUTH_ENTRY_LOGIN_2]:
            response = dispatch_to_register()
        elif auth_entry in [AUTH_ENTRY_REGISTER, AUTH_ENTRY_REGISTER_2]:
            response = dispatch_to_register()
        elif auth_entry == AUTH_ENTRY_ACCOUNT_SETTINGS:
            raise AuthEntryError(
                backend, 'auth_entry is wrong. Settings requires a user.')
        else:
            raise AuthEntryError(backend, 'auth_entry invalid')
    else:
        if user.id != 1:
            user.email = data['email']
            user.username = data['username']
            user.first_name = data['firstname']
            user.last_name = data['lastname']
            user.save()
            create_comments_service_user(user)

        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        except UserProfile.MultipleObjectsReturned:
            user_profile = UserProfile.objects.filter(user=user)[0]

        if user_profile:
            user_profile.name = user.get_full_name()
            user_profile.goals = json.dumps(data.get('meta', {}))
            user_profile.save()

    user = user or response.get('user')
    if user and not user.is_active:
        if allow_inactive_user:
            pass
        elif social is not None:
            reactivation_email_for_user(user)
            log.warning(
                'User "%s" is using third_party_auth to login but has not yet activated their account. ',
                user.username
            )

    # add roles for User
    permissions = kwargs.get('response', {}).get('permissions')
    if permissions is not None:
        try:
            set_roles_for_edx_users(user, permissions, strategy)
        except Exception as e:
            log.error(u'set_roles_for_edx_users error: {}'.format(e))

    return response


def apply_user_preferences(strategy, *args, **kwargs):
    """
    Pushes values from sso to edx as UserPreference according to the PREFERENCE_KEY_LIST
    """
    data = kwargs.get('response', False)
    user = kwargs.get('user', False)
    if not data:
        log.error("No data in pipeline 'apply_user_preferences'")
        return
    if not user:
        log.error("No user in pipeline 'apply_user_preferences'")
        return

    user_preferences = UserPreference.objects.filter(user=user)
    for key in PREFERENCE_KEY_LIST:
        up_for_key = user_preferences.filter(key=key).first()
        if not up_for_key:
            UserPreference.objects.create(user=user, key=key, value=data[key])
        elif up_for_key.value != data[key]:
            if data[key]:
                up_for_key.value = data[key]
                up_for_key.save()
            else:
                up_for_key.delete()
    return
