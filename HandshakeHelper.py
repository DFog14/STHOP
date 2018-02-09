#!/usr/bin/env python3
import sys
import re
import json


class HandshakeHelper(object):
    def __init__(self):
        self.pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}'
        self.json_data = []

    def domain_reader(self, file):
        """
        Extracts all domains from given file and wraps them as a json object.
        :param file: File of any type containing any amount of domains.
        :return: None
        """
        try:
            with open(file, 'r') as domain_file:
                regex_match = re.findall(self.pattern, domain_file.read())
                self.json_data = json.dumps(regex_match)
                print(self.json_data)
        except FileNotFoundError:
            print(file+' was not found.')
            sys.exit()
