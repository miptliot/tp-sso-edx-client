from django.conf import settings


def edx_context(request):
    gtm_id = None
    if request.user.is_authenticated():
        items = request.user.social_auth.filter(provider__in=('sso_tp-oauth2', 'sso_tp_cms-oauth2'))
        for item in items:
            if isinstance(item.extra_data, dict) and isinstance(item.extra_data.get('gtm_id'), (str, unicode)) and item.extra_data.get('gtm_id'):
                gtm_id = item.extra_data.get('gtm_id')
                break
    return {
        'USER_GTM_ID': gtm_id,
        'ADDITIONAL_JS_CODE_HEAD': getattr(settings, 'ADDITIONAL_JS_CODE_HEAD', None),
        'ADDITIONAL_JS_CODE_BODY': getattr(settings, 'ADDITIONAL_JS_CODE_BODY', None),
    }

