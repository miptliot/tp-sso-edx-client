# coding: utf-8

import logging
import urllib

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth import get_user_model
from django.shortcuts import redirect

from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response

User = get_user_model()

try:
    from opaque_keys.edx.keys import CourseKey
    is_edx = True
except ImportError:
    is_edx = False


def logout(request, next_page=None,
           redirect_field_name=REDIRECT_FIELD_NAME, *args, **kwargs):
    """
    This view needed for correct redirect to sso-logout page
    """
    if (redirect_field_name in request.POST or
            redirect_field_name in request.GET):
        next_page = request.POST.get(redirect_field_name,
                                     request.GET.get(redirect_field_name))

    if next_page:
        next_page = request.build_absolute_uri(next_page)
    else:
        next_page = request.build_absolute_uri('/')

    if next_page:
        next_page = urllib.quote(next_page)

    return redirect('%s?%s=%s' % (settings.SOCIAL_AUTH_LOGOUT_URL,
                                      redirect_field_name, next_page))


class ApiKeyPermission(permissions.BasePermission):
    """
    Check Api key
    """
    def has_permission(self, request, view):
        if is_edx:
            setting_name = 'EDX_API_KEY'
            header_name = 'HTTP_X_EDX_API_KEY'
        else:
            setting_name = 'PLP_API_KEY'
            header_name = 'HTTP_X_PLP_API_KEY'
        api_key = getattr(settings, setting_name, None)
        if not api_key:
            logging.error('%s not configured' % setting_name)
        key = request.META.get(header_name)
        if key and api_key and key == api_key:
            return True
        return False


class DeactivateUsersAPIView(APIView):
    """
        **Описание**

            Активация/деактивация пользователей

        **Пример запроса**

            POST /api/deactivate/{
                "users": ["username"],
                "activate": true,
            }

        **Параметры post-запроса**

            * users - логины пользователей
            * activate - необязательный параметр, если true - то активируем пользователя

        **Пример ответа**

            Словарь с количеством обновленных записей пользователей и новым статусом is_active

            * {"users_count": 1, "is_active": False}

    """
    permission_classes = (ApiKeyPermission, )

    def post(self, request):
        users = request.data.getlist('users')
        activate = bool(request.data.get('activate'))
        users_cnt = User.objects.filter(username__in=users).update(is_active=activate)
        return Response({'users_count': users_cnt, 'is_active': activate})
