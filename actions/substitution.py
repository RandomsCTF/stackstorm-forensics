#!/usr/bin/python

import requests
import re
from st2actions.runners.pythonrunner import Action

__all__ = [
    'SubstitutionAction'
]


class SubstitutionAction(Action):
    def run(self, ciphertext):
        page = requests.post("http://quipqiup.com/index.php", {
            'mode': '3',
            'clues': '',
            'action': 'Solve',
            'ciphertext': ciphertext
        })
        expression = '\<script\>solsum.*?\"(.*?)\"'
        result = re.search(expression, page.text)
        return result.group(1)
