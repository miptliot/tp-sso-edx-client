from django.conf.urls import include, patterns, url


urlpatterns = patterns(
    '',
    url(r'', include('cms.urls')),
    url(r'', include('third_party_auth.urls')),
    url(r'^social-logout', 'sso_edx_npoed.views.logout', name='social-logout'),
)
