from django.conf.urls import include, url
from contentstore.views import render_404, render_500
from sso_edx_tp.views import logout

urlpatterns = [
    url(r'^404$', render_404),
    url(r'^500$', render_500),
    url(r'', include('cms.urls')),
    url(r'', include('third_party_auth.urls')),
    url(r'^social-logout', logout, name='social-logout'),
]
