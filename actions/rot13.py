#!/usr/bin/python

import codecs
from st2actions.runners.pythonrunner import Action

__all__ = [
    'Rot13Action'
]


class Rot13Action(Action):
    def run(self, string):
        return codecs.encode(string, 'rot_13')
