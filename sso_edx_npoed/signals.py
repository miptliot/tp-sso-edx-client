import os
import logging
import requests
from datetime import datetime

from django.conf import settings
from django.dispatch import receiver
from django.db.models.signals import post_save, post_delete

from courseware.courses import get_course
from xmodule.modulestore.django import SignalHandler
from student.models import CourseEnrollment


log = logging.getLogger('SSO_signals')


@receiver(SignalHandler.course_published)
def push_objects_to_sso(sender, course_key, **kwargs):
    if not hasattr(settings, 'SSO_API_URL'):
        log.error('settings.SSO_API_URL is not defined')
        return

    if not hasattr(settings, 'SSO_API_TOKEN'):
        log.error('SSO_API_TOKEN is not defined')
        return

    url = os.path.join(settings.SSO_API_URL, 'course/')
    sso_api_headers = {'Authorization': 'Token {}'.format(settings.SSO_API_TOKEN)}
    course = get_course(course_key)
    name = course.name or course_key.run
    start = course.start and datetime.strftime(course.start, '%Y-%m-%dT%H:%M:%SZ') or None
    end = course.end and datetime.strftime(course.end, '%Y-%m-%dT%H:%M:%SZ') or None
    data = {
        'name': name,
        'course_id': course_key.html_id(),
        'start': start,
        'end': end,
        'org': course.org,
        'run': course_key.run,
    }

    r = requests.post(url, headers=sso_api_headers, data=data)

    if r.ok:
        return r.text
    log.error('API "{}" returned: {}'.format(url, r.status_code))


@receiver(post_save, sender=CourseEnrollment)
def push_enrollment_to_sso(sender, instance, **kwargs):
    if not hasattr(settings, 'SSO_API_URL'):
        log.error('settings.SSO_API_URL is not defined')
        return 

    if not hasattr(settings, 'SSO_API_TOKEN'):
        log.error('SSO_API_TOKEN is not defined') 
        return

    sso_enrollment_api_url = os.path.join(settings.SSO_API_URL, 'enrollment/')
    sso_api_headers = {'Authorization': 'Token {}'.format(settings.SSO_API_TOKEN)}

    data = {
        'mode': instance.mode,
        'is_active': instance.is_active,
        'course_id': str(instance.course.id),
        'course_run': instance.course.id.run,
        'user': instance.user.username
    }
    r = requests.post(sso_enrollment_api_url, headers=sso_api_headers, data=data)
    if r.ok:
        return r.text
    log.error('API "{}" returned: {}'.format(sso_enrollment_api_url, r.status_code))



@receiver(post_delete, sender=CourseEnrollment)
def delete_enrollment_from_sso(sender, instance, **kwargs):
    if not hasattr(settings, 'SSO_API_URL'):
        log.error('settings.SSO_API_URL is not defined')
        return 

    if not hasattr(settings, 'SSO_API_TOKEN'):
        log.error('SSO_API_TOKEN is not defined') 
        return

    sso_enrollment_api_url = os.path.join(settings.SSO_API_URL, 'enrollment/')
    sso_api_headers = {'Authorization': 'Token {}'.format(settings.SSO_API_TOKEN)}

    data = {
        'course_id': str(instance.course.id),
        'course_run': instance.course.id.run,
        'user': instance.user.username
    }

    r = requests.delete(sso_enrollment_api_url, sso_api_headers=headers, data=data)
    if r.ok:
        return r.text
    log.error('API "{}" returned: {}'.format(sso_enrollment_api_url, r.status_code))
