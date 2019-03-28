from django.contrib import admin
from .models import SSORedirect


@admin.register(SSORedirect)
class SSORedirectAdmin(admin.ModelAdmin):
    list_display = ('site', 'sso_domain')
