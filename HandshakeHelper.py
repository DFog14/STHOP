#!/usr/bin/env python3
import sys
import csv
import json


class HandshakeHelper(object):
    def __init__(self):
        self.json_data = []

    def domain_reader(self, file, dialect='excel'):
        try:
            if file.endswith('.txt'):
                with open(file) as txt_file:
                    self.json_data = [x[:-2] for x in txt_file]
            else:
                with open(file, newline='') as csv_file:
                    csv_reader = csv.reader(csv_file, dialect)
                    self.json_data = [x for x in csv_reader]
                    print(self.json_data)
                    #print(self.json_data)
        except FileNotFoundError:
            print(file+' was not found.')
            sys.exit()
