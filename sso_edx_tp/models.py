import os
import logging
import requests

from django.conf import settings
from django.contrib.sites.models import Site, _simple_domain_name_validator
from django.dispatch import receiver
from django.db import models
from django.db.models.signals import post_save
from django.utils.translation import ugettext_lazy as _

from xmodule.modulestore.django import SignalHandler
from course_action_state.models import CourseRerunState


log = logging.getLogger('SSO_signals')


class SSORedirect(models.Model):
    site = models.OneToOneField(Site, on_delete=models.CASCADE, verbose_name=_('Site'))
    sso_domain = models.CharField(
        verbose_name=_('SSO domain name'),
        max_length=100,
        validators=[_simple_domain_name_validator],
    )
    
    class Meta:
        verbose_name = _('SSO Redirect')
        verbose_name_plural = _('SSO Redirects')


@receiver(SignalHandler.course_published)
def push_objects_to_sso(sender, course_key, **kwargs):
    if course_key.branch:
        return

    if not hasattr(settings, 'SSO_API_URL'):
        log.error('settings.SSO_API_URL is not defined')
        return

    if not hasattr(settings, 'SSO_API_KEY'):
        log.error('SSO_API_KEY is not defined')
        return

    url = os.path.join(settings.SSO_API_URL, 'course/')
    sso_api_headers = {'x-sso-api-key': settings.SSO_API_KEY}
    data = {
        'course_id': course_key.html_id(),
        'org': course_key.org,
        'course': course_key.course,
        'run': course_key.run,
    }

    r = requests.post(url, headers=sso_api_headers, json=data)

    if r.ok:
        return r.text
    log.error('API "{}" returned: {}'.format(url, r.status_code))


@receiver(post_save, sender=CourseRerunState)
def push_objects_to_sso_past_rerun(sender, instance, **kwargs):
    """
    Only on succeeded rerun state sync rerun object to sso
    """
    if instance.state == 'succeeded':
        push_objects_to_sso(sender=sender, course_key=instance.course_key,
                            **kwargs)

