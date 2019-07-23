from datetime import timedelta
import logging
import time
import uuid

from Cryptodome.PublicKey.RSA import importKey
from django.utils import dateformat, timezone
from jwkest.jwk import RSAKey as jwk_RSAKey
from jwkest.jwk import SYMKey, load_jwks_from_url
from jwkest.jws import (
    JWS,
    BadSignature,
    NoSuitableSigningKeys
)

from jwkest.jwt import JWT

from oidc_provider.lib.errors import TokenError
from oidc_provider.lib.utils.common import (
    get_issuer,
    run_processing_hook,
    get_site_url
)
from oidc_provider.lib.claims import StandardScopeClaims
from oidc_provider.models import (
    Code,
    RSAKey,
    Token,
)
from oidc_provider import settings

logger = logging.getLogger(__name__)


def create_id_token(token, user, aud, nonce='', at_hash='', request=None, scope=None):
    """
    Creates the id_token dictionary.
    See: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    Return a dic.
    """
    if scope is None:
        scope = []
    sub = settings.get('OIDC_IDTOKEN_SUB_GENERATOR', import_str=True)(user=user)

    expires_in = settings.get('OIDC_IDTOKEN_EXPIRE')

    # Convert datetimes into timestamps.
    now = int(time.time())
    iat_time = now
    exp_time = int(now + expires_in)
    user_auth_time = user.last_login or user.date_joined
    auth_time = int(dateformat.format(user_auth_time, 'U'))

    dic = {
        'iss': get_issuer(request=request),
        'sub': sub,
        'aud': str(aud),
        'exp': exp_time,
        'iat': iat_time,
        'auth_time': auth_time,
    }

    if nonce:
        dic['nonce'] = str(nonce)

    if at_hash:
        dic['at_hash'] = at_hash

    # Inlude (or not) user standard claims in the id_token.
    if settings.get('OIDC_IDTOKEN_INCLUDE_CLAIMS'):
        if settings.get('OIDC_EXTRA_SCOPE_CLAIMS'):
            custom_claims = settings.get('OIDC_EXTRA_SCOPE_CLAIMS', import_str=True)(token)
            claims = custom_claims.create_response_dic()
        else:
            claims = StandardScopeClaims(token).create_response_dic()
        dic.update(claims)

    dic = run_processing_hook(
        dic, 'OIDC_IDTOKEN_PROCESSING_HOOK',
        user=user, token=token, request=request)

    return dic


def encode_id_token(payload, client):
    """
    Represent the ID Token as a JSON Web Token (JWT).
    Return a hash.
    """
    keys = get_client_alg_keys(client)
    _jws = JWS(payload, alg=client.jwt_alg)
    return _jws.sign_compact(keys)


def decode_id_token(token, client):
    """
    Represent the ID Token as a JSON Web Token (JWT).
    Return a hash.
    """
    keys = get_client_alg_keys(client)
    return JWS().verify_compact(token, keys=keys)


def validate_private_jwt(client_assertion, client, request):
    """
    Validate JWT according to OpenID Section 1.9, private_key_jwt

    https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication

    Tries public_key first then fetches new keys and tries those if it fails.
    Updates public_key for later use if one succeds that doesn't match current
    public_key.
    """
    fetch = False
    cur_key = client.public_key
    payload = None

    while True:
        if cur_key and not fetch:
            pub_keys = [jwk_RSAKey(key=importKey(cur_key))]
            pub_keys[0].add_kid()
        else:
            pub_keys = load_jwks_from_url(client.public_key_url)
            fetch = True

        for key in pub_keys:
            try:
                # Signature checked here
                # Doing each key one at a time so we know which one succeeds
                payload = JWS().verify_compact(client_assertion, keys=[key])
                key_str = key.key.export_key().decode('utf-8')
                if key_str != cur_key:
                    client.public_key = key_str
                    client.save()
                    logger.debug("Updated public key")
                break
            except (BadSignature, NoSuitableSigningKeys) as e:
                if fetch:
                    logger.debug("No valid keys: {}".format(e))
                    raise TokenError('invalid_request')
                else:
                    logger.debug("Stored key didn't work; fetching new key")
                    fetch = True
        if payload:
            break

    site_url = get_site_url(request)
    _validate_jwt_payload(payload, site_url)


def _validate_jwt_payload(payload, site_url):
    """Validate JWT payload contents

    - oauth bearer: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12#section-3
    - client auth: https://tools.ietf.org/html/draft-ietf-oauth-assertions-18#section-4.2
    """
    required = {'iss', 'sub', 'aud', 'jti', 'exp'}
    for field in required:
        if not payload.get(field):
            logger.debug('[Token] Missing JWT claim: %s', field)
            raise TokenError('invalid_request', "Missing {} claim".format(field))

    # Specific requirements
    # https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12#section-3
    # 3.1 - iss - Checked above
    # 3.2 - sub == client_id. Already checked b/c we have a client
    # 3.3 - aud
    aud = payload.get('aud', '')
    if not aud.startswith(site_url):
        logger.debug("[Token] JWT 'aud' does not start with %s", site_url)
        raise TokenError('invalid_request', "Invalid aud claim: {}".foramt(aud))

    # 3.4 - exp
    exp = payload.get('exp')
    if not exp or exp <= timezone.now().timestamp():
        logger.debug("[Token] JWT expired or missing; exp: %s", exp)
        raise TokenError("invalid_request", "exp claim is expired or missing: {}"
                         .format(exp))


def validate_secret_jwt(client_assertion, client, secret, request):
    """Validate JWT for a client_secret_jwt according to OpenID Core, Section 9

    https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
    """
    # TODO: Needs to be implemented
    raise NotImplementedError
    # Validate signature using shared secret
    # site_url = get_site_url(request)
    # _validate_jwt_payload(payload, site_url)


def client_id_from_id_token(id_token):
    """
    Extracts the client id from a JSON Web Token (JWT).
    Returns a string or None.
    """
    payload = JWT().unpack(id_token).payload()
    aud = payload.get('aud', None)
    if aud is None:
        return None
    if isinstance(aud, list):
        return aud[0]
    return aud


def create_token(user, client, scope, id_token_dic=None):
    """
    Create and populate a Token object.
    Return a Token object.
    """
    token = Token()
    token.user = user
    token.client = client
    token.access_token = uuid.uuid4().hex

    if id_token_dic is not None:
        token.id_token = id_token_dic

    token.refresh_token = uuid.uuid4().hex
    token.expires_at = timezone.now() + timedelta(
        seconds=settings.get('OIDC_TOKEN_EXPIRE'))
    token.scope = scope

    return token


def create_code(user, client, scope, nonce, is_authentication,
                code_challenge=None, code_challenge_method=None):
    """
    Create and populate a Code object.
    Return a Code object.
    """
    code = Code()
    code.user = user
    code.client = client

    code.code = uuid.uuid4().hex

    if code_challenge and code_challenge_method:
        code.code_challenge = code_challenge
        code.code_challenge_method = code_challenge_method

    code.expires_at = timezone.now() + timedelta(
        seconds=settings.get('OIDC_CODE_EXPIRE'))
    code.scope = scope
    code.nonce = nonce
    code.is_authentication = is_authentication

    return code


def get_client_alg_keys(client):
    """
    Takes a client and returns the set of keys associated with it.
    Returns a list of keys.
    """
    if client.jwt_alg == 'RS256':
        keys = []
        for rsakey in RSAKey.objects.all():
            keys.append(jwk_RSAKey(key=importKey(rsakey.key), kid=rsakey.kid))
        if not keys:
            raise Exception('You must add at least one RSA Key.')
    elif client.jwt_alg == 'HS256':
        keys = [SYMKey(key=client.client_secret, alg=client.jwt_alg)]
    else:
        raise Exception('Unsupported key algorithm.')

    return keys
