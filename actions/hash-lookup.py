#!/usr/bin/python

import requests
from st2actions.runners.pythonrunner import Action

__all__ = [
    'HashLookupAction'
]

reply = """decrypted your hash, dude! It's \"%s\".
Found it on leakdb.net, just so you know."""


class HashLookupAction(Action):
    def run(self, hash):
        request = requests.get('https://api.leakdb.net/?j=%s' % hash)
        json = request.json()
        if json['found'] == 'true':
            value = json['hashes'][0]['plaintext']
            return reply % (value)
        else:
            return "can't find anything on leakdb, sorry. :("
