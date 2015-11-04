#!/usr/bin/python

import requests
import re
import HTMLParser
from st2actions.runners.pythonrunner import Action

__all__ = [
    'VigenereAction'
]


class VigenereAction(Action):
    def run(self, ciphertext):
        h = HTMLParser.HTMLParser()
        get = requests.get("http://www.guballa.de/vigenere-solver").text
        token = re.search('name="REQUEST_TOKEN" value="(.*?)"', get).group(1)
        post = requests.post("http://www.guballa.de/vigenere-solver", {
            'REQUEST_TOKEN': token,
            'cipher': ciphertext,
            'variant': 'vigenere',
            'lang': 'en',
            'key_len': '3-30',
            'break': 'Break Cipher'
        })
        key_regex = 'Clear text using key \"(.*?)\"'
        decrypted_regex = 'name=\"clear_text\"\>(.*?)\<'
        key = re.search(key_regex, post.text).group(1)
        message = re.search(decrypted_regex, post.text, re.DOTALL).group(1)
        message = h.unescape(message)
        return "my best guess for the key is \"%s\": ```%s```" % (key, message)
