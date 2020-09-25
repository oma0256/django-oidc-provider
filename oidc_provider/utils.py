import urlparse


def parse_lti_message_hint(msg_hint):
    parsed = urlparse.parse_qs(msg_hint)
    msg_type = parsed.get('msg')[0]
    user_id = parsed.get('user_id')[0]
    loc = msg_hint.replace('&msg={}&user_id={}'.format(msg_type, user_id), '')
    return (loc, msg_type)
