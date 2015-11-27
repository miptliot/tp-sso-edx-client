from django.conf.urls import include, patterns, url


handler404 = 'contentstore.views.render_404'
handler500 = 'contentstore.views.render_500'

urlpatterns = patterns(
    '',
    url(r'^404$', handler404),
    url(r'^500$', handler500),
    url(r'', include('cms.urls')),
    url(r'', include('third_party_auth.urls')),
    url(r'^social-logout', 'sso_edx_npoed.views.logout', name='social-logout'),
)
