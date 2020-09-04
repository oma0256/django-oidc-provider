import urlparse

from cryptography.fernet import Fernet

from django.conf import settings
from django.utils import timezone
from django.utils.http import urlquote

from ibl_cryptography_app.models import FernetKey

from opaque_keys.edx.keys import UsageKey

import logging

log = logging.getLogger(__name__)


def fernet_decode_text(encoded_text, usage_id):
    log.info('fernet_decode_text................')
    fernet_keys = FernetKey.objects.filter(
        user_id=encoded_text, usage_id=UsageKey.from_string(usage_id)
    )
    log.info(fernet_keys)
    if fernet_keys.count() != 1:
        raise Exception('Many keys are associated to this user and xblock')
    fernet_key = fernet_keys[0]
    log.info(fernet_key)
    time_since_key_was_created = (timezone.now() - fernet_key.created).seconds
    log.info(time_since_key_was_created)
    if time_since_key_was_created > 60:
        raise Exception('This key has expired')
    log.info(fernet_key.key)
    cipher_suite = Fernet(str(fernet_key.key))
    log.info(cipher_suite)
    decoded_text = cipher_suite.decrypt(b'{}'.format(encoded_text))
    log.info(decoded_text)
    return decoded_text


def parse_lti_message_hint(msg_hint, decoded_user_id=True):
    log.info('msg_hint...................')
    log.info(msg_hint)
    parsed = urlparse.parse_qs(msg_hint)
    msg_type = parsed.get('msg')[0]
    log.info(msg_type)
    user_id = parsed.get('user_id')[0]
    log.info(user_id)
    user_id = urlquote(user_id) if decoded_user_id is True else user_id
    log.info(user_id)
    loc = msg_hint.replace('&msg={}&user_id={}'.format(msg_type, user_id), '')
    return (loc, msg_type)
