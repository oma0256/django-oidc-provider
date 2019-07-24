from hashlib import sha224
from random import randint
from textwrap import wrap
from uuid import uuid4

from Cryptodome.PublicKey.RSA import importKey

from django.forms import ModelForm, ValidationError
from django.contrib import admin
from django.utils.translation import ugettext_lazy as _

from oidc_provider.models import Client, Code, Token, RSAKey, AuthMethods


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

    def clean_public_key(self):
        """Ensure public_key is formatted correctly to be used by tools"""
        key = self.cleaned_data['public_key'].strip()
        # Empty is OK
        if not key:
            return key

        if 'PRIVATE KEY' in key:
            raise ValidationError('This field expects a PUBLIC KEY')

        begin = ('-----BEGINPUBLICKEY-----', '-----BEGIN PUBLIC KEY-----\n')
        end = ('-----ENDPUBLICKEY-----', '\n-----END PUBLIC KEY-----')

        # Remove all whitespace and newlines
        key = "".join(key.split())
        if not key.startswith(begin[0]):
            raise ValidationError(
                'Public key must start with: -----BEGIN PUBLIC KEY-----'
            )
        if not key.endswith(end[0]):
            raise ValidationError(
                'Public key must end with: -----END PUBLIC KEY-----'
            )
        key = key.replace(begin[0], '').replace(end[0], '')
        key = '\n'.join(wrap(key, 64))
        key = "{}{}{}".format(begin[1], key, end[1])

        # Import key to make sure it will work later
        try:
            importKey(key)
        except Exception as e:
            # TODO: catch specific errors and translate them into something
            # more meaningful to the user
            # Ex: 'Incorrect padding' - that doesn't mean anything to user
            raise ValidationError('Unable to process key: {}'.format(e))

        return key

    def clean(self):
        """Ensure pub_key present for private_key_jwt authentication"""
        cleaned = super(ClientForm, self).clean()

        # Wait until all other errors are fixed before bothering with this
        if self.errors:
            return cleaned

        auth_type = cleaned['auth_type']

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
