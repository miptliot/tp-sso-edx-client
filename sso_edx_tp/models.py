import logging

from django.contrib.sites.models import Site, _simple_domain_name_validator
from django.db import models
from django.utils.translation import ugettext_lazy as _

try:
    from .signals import push_objects_to_sso, push_objects_to_sso_past_rerun
except ImportError:
    pass


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
