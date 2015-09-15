#!/usr/bin/python

from lib.hashtag import identify_hash
from st2actions.runners.pythonrunner import Action

__all__ = [
    'HashIdentifierAction',
]


class HashIdentifierAction(Action):
    def run(self, hash):
        return ", ".join(identify_hash(hash)[:3])
