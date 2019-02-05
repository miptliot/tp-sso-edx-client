import logging

from student.roles import (GlobalStaff, CourseStaffRole, CourseInstructorRole,
                           CourseCreatorRole)
from student.models import CourseAccessRole
from django_comment_common.models import (
    FORUM_ROLE_ADMINISTRATOR, FORUM_ROLE_MODERATOR, FORUM_ROLE_COMMUNITY_TA,
    FORUM_ROLE_STUDENT, Role, Permission
)
from opaque_keys.edx.keys import CourseKey


log = logging.getLogger(__name__)

# Role name for OrgStaffRole, OrgInstructorRole has hardcoded in __init__ method ("staff" and "instructor")
LIBRARY_CREATE_ROLES = [
    'staff',
    'instructor',
    CourseInstructorRole.ROLE,
    CourseStaffRole.ROLE,
    CourseCreatorRole.ROLE
]

PERMISSION_FORUM_ROLES = {
    FORUM_ROLE_ADMINISTRATOR : [
        u'create_comment', u'create_sub_comment', u'create_thread',
        u'delete_comment', u'delete_thread', u'edit_content',
        u'endorse_comment', u'follow_commentable', u'follow_thread',
        u'manage_moderator', u'openclose_thread', u'see_all_cohorts',
        u'unfollow_commentable', u'unfollow_thread', u'unvote',
        u'update_comment', u'update_thread', u'vote'
    ],
    FORUM_ROLE_MODERATOR : [
        u'create_comment', u'create_sub_comment', u'create_thread',
        u'delete_comment', u'delete_thread', u'edit_content', u'vote',
        u'endorse_comment', u'follow_commentable', u'follow_thread',
        u'openclose_thread', u'see_all_cohorts', u'unfollow_commentable',
        u'unfollow_thread', u'unvote', u'update_comment', u'update_thread'
    ],
    FORUM_ROLE_COMMUNITY_TA: [
        u'create_comment', u'create_sub_comment', u'create_thread',
        u'delete_comment', u'delete_thread', u'edit_content', u'vote',
        u'endorse_comment', u'follow_commentable', u'follow_thread',
        u'openclose_thread', u'see_all_cohorts', u'unfollow_commentable',
        u'unfollow_thread', u'unvote', u'update_comment', u'update_thread'
    ],
    FORUM_ROLE_STUDENT : [
        u'create_comment', u'create_sub_comment', u'create_thread', u'vote',
        u'follow_commentable', u'follow_thread', u'unfollow_commentable',
        u'unfollow_thread', u'unvote', u'update_comment', u'update_thread'
    ]
}

def can_create_library(user):
    qs = CourseAccessRole.objects.filter(user_id=user.id,
                                         role__in=LIBRARY_CREATE_ROLES)
    if callable(user.is_authenticated):
        user_is_authenticated = user.is_authenticated()
    else:
        user_is_authenticated = user.is_authenticated

    is_library_creator = (
        user_is_authenticated
        and user.is_active
        and (
            GlobalStaff().has_user(user)
            or qs.exists()
        )
    )

    return is_library_creator


def create_forum_roles_and_permissions_for_cours(course):
    '''
    Create roles and permissions for course.

    For example:

    >>> from sso_edx_tp.utils import create_forum_roles_and_permissions_for_cours
    >>> create_forum_roles_and_permissions_for_cours('edX/DemoX/Demo_Course')
    ...

    '''
    course_id = CourseKey.from_string(course)
    for item in PERMISSION_FORUM_ROLES.keys():
        r, created = Role.objects.get_or_create(course_id=course_id, name=item)
        if created:
            log.warning(u'Created role {} for course {}.'.format(r, course))
        perms = Permission.objects.filter(name__in=PERMISSION_FORUM_ROLES[item])
        for perm in perms:
            if not r.permissions.filter(name=perm.name):
                r.permissions.add(perm)
                log.warning(u'Add permission {} for role {}.'.format(perm, r))
