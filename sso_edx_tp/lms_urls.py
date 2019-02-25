from django.conf.urls import include, url
from static_template_view.views import render_404, render_500
from sso_edx_tp.views import logout

urlpatterns = [
    url(r'^404$', render_404),
    url(r'^500$', render_500),
    url(r'', include('lms.urls')),
    url(r'^social-logout', logout, name='social-logout'),
]
