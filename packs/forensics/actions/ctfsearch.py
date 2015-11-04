#!/usr/bin/python

import ics
import requests
import arrow
import re

from st2actions.runners.pythonrunner import Action

__all__ = [
    'CTFSearchAction'
]


class CTFSearchAction(Action):
    def run(self, query):
        calendar = 'https://www.google.com/calendar/ical/ctftime%40gmail.com/public/basic.ics'
        contents = requests.get(calendar).text
        contents = re.sub(r'(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z',
                          r'\1-\2-\3T\4:\5',
                          contents)
        ctfs = ics.Calendar(contents)
        for event in ctfs.events[arrow.utcnow():]:
            if not query or (query.lower() in event.name.lower()):
                url = re.search('URL: (.*?)\n', event.description)
                return "%s starts %s%s" % (
                    event.name,
                    event.begin.humanize(),
                    " (%s)" % (url.group(1)) if url else "",
                )
        return "can't find upcoming CTFs matching \"%s\" :(" % (query)
