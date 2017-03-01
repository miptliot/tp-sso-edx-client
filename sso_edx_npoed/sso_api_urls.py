# coding: utf-8

from django.conf.urls import url
from .views import DeactivateUsersAPIView


urlpatterns = [
    url('^sso/deactivate-users/?$', DeactivateUsersAPIView.as_view()),
]
