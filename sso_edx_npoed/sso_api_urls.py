# coding: utf-8

from django.conf.urls import url
from .views import DeactivateUsersAPIView


urlpatterns = [
    url('^api/sso-deactivate-users/?$', DeactivateUsersAPIView.as_view()),
]
