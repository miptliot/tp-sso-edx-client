from django.conf.urls import include, patterns, url

# Custom error pages
handler404 = 'static_template_view.views.render_404'
handler500 = 'static_template_view.views.render_500'


urlpatterns = patterns(
    '',
    url(r'^404$', handler404),
    url(r'^500$', handler500),
    url(r'', include('lms.urls')),
    url(r'^social-logout', 'sso_edx_tp.views.logout', name='social-logout'),
)
