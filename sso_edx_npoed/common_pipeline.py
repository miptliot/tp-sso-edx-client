# coding: utf-8

from django.db import transaction
import requests
from social.exceptions import AuthForbidden


def try_to_set_password(*args, **kwargs):
    user = kwargs.get('user')
    if user and (user.is_staff or user.is_superuser):
        backend = kwargs.get('backend')
        if backend and hasattr(backend, 'get_password_hash') and kwargs.get('access_token'):
            try:
                p_hash = backend.get_password_hash(kwargs['access_token']).get('hash')
                if p_hash and not p_hash.startswith('!'):
                    user.password = p_hash
                    user.save()
            except (requests.RequestException, ValueError):
                pass


def check_active_status(*args, **kwargs):
    user = kwargs.get('user')
    backend = kwargs.get('backend')
    if user and not user.is_active and backend and hasattr(backend, 'check_user_active_status') and transaction.get_autocommit():
        if not backend.check_user_active_status(user).get('active'):
            raise AuthForbidden(backend)
        user.is_active = True
