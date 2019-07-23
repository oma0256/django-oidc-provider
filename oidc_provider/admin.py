from hashlib import sha224
from random import randint
from uuid import uuid4

from django.forms import ModelForm, ValidationError
from django.contrib import admin
from django.utils.translation import ugettext_lazy as _

from oidc_provider.models import Client, Code, Token, RSAKey, AuthMethods
from oidc_provider import settings


class ClientForm(ModelForm):

    class Meta:
        model = Client
        exclude = []

    def __init__(self, *args, **kwargs):
        super(ClientForm, self).__init__(*args, **kwargs)
        self.fields['client_id'].required = False
        self.fields['client_id'].widget.attrs['disabled'] = 'true'
        self.fields['client_secret'].required = False
        self.fields['client_secret'].widget.attrs['disabled'] = 'true'

    def clean_client_id(self):
        instance = getattr(self, 'instance', None)
        if instance and instance.pk:
            return instance.client_id
        else:
            return str(randint(1, 999999)).zfill(6)

    def clean_client_secret(self):
        instance = getattr(self, 'instance', None)

        secret = ''

        if instance and instance.pk:
            if (self.cleaned_data['client_type'] == 'confidential') and not instance.client_secret:
                secret = sha224(uuid4().hex.encode()).hexdigest()
            elif (self.cleaned_data['client_type'] == 'confidential') and instance.client_secret:
                secret = instance.client_secret
        else:
            if (self.cleaned_data['client_type'] == 'confidential'):
                secret = sha224(uuid4().hex.encode()).hexdigest()

        return secret

    def clean_auth_type(self):
        """Ensure SITE_URL is set if using jwt related auth method"""
        auth_type = self.cleaned_data['auth_type']
        if auth_type == AuthMethods.private_jwt or auth_type == AuthMethods.secret_jwt:
            priv = AuthMethods.private_jwt.name
            secret = AuthMethods.secret_jwt.name
            if not settings.get('SITE_URL'):
                raise ValidationError(
                    'SITE_URL must be set to use {} or {}'.format(priv, secret))
        return auth_type

    def clean(self):
        """Ensure pub_key present for private_key_jwt authentication"""
        cleaned = super().clean()
        auth_type = cleaned['auth_type']
        # Ensure SITE_URL set for jwt auth methods

        if auth_type == AuthMethods.private_jwt.value:
            pub_key = cleaned.get('public_key', '')
            pub_key_url = cleaned.get('public_key_url', '')
            if not pub_key and not pub_key_url:
                raise ValidationError(
                    'When using Client Auth Type {}, Public Key or Public Key '
                    'URL must be set'.format(
                        dict(self.fields['auth_type'].choices)[auth_type]))
        return cleaned



@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):

    fieldsets = [
        [_(u''), {
            'fields': (
                'name', 'owner', 'client_type', 'response_types', '_redirect_uris', 'jwt_alg',
                'require_consent', 'reuse_consent'),
        }],
        [_(u'Authentication'), {
            'fields': ('auth_type', 'public_key', 'public_key_url'),
        }],
        [_(u'Credentials'), {
            'fields': ('client_id', 'client_secret', '_scope'),
        }],
        [_(u'Information'), {
            'fields': ('contact_email', 'website_url', 'terms_url', 'logo', 'date_created'),
        }],
        [_(u'Session Management'), {
            'fields': ('_post_logout_redirect_uris',),
        }],
    ]
    form = ClientForm
    list_display = ['name', 'client_id', 'response_type_descriptions', 'date_created']
    readonly_fields = ['date_created']
    search_fields = ['name']
    raw_id_fields = ['owner']


@admin.register(Code)
class CodeAdmin(admin.ModelAdmin):

    def has_add_permission(self, request):
        return False


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):

    def has_add_permission(self, request):
        return False


@admin.register(RSAKey)
class RSAKeyAdmin(admin.ModelAdmin):

    readonly_fields = ['kid']
