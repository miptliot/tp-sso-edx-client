# coding: utf-8

import requests


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
