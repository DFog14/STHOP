#!/usr/bin/env python3
import sys
import re
import socket
import ssl
from multiprocessing.pool import ThreadPool as Pool
import json


class HandshakeHelper(object):
    def __init__(self):
        self.pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)' \
                       r'+[a-zA-Z]{2,6}'
        self.domains = []

    def domain_reader(self, file):
        """
        Extracts all domains from given file.
        :param file: File of any type containing any amount of domains.
        :return: None
        """
        try:
            with open(file, 'r') as domain_file:
                return re.findall(self.pattern, domain_file.read())
        except FileNotFoundError:
            print(file+' was not found.')
            sys.exit()

    def extract_data(self, domain):
        """
        Extracts IP Address, CipherSuite, and SSL Version and stores into a 
        dictionary
        :param domain: Domain Name 
        :return: Dictionary
        """
        try:
            domain_info = dict({'domain': '', 'ip_address': '', 'ciphersuite:': '',
                              'version': ''})
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            ssl_sock = ssl.wrap_socket(sock)
            ssl_sock.connect((domain, 443))
            domain_info['domain'] = domain
            domain_info['ip_address'] = ssl_sock.getpeername()[0]
            domain_info['ciphersuite'] = ssl_sock.cipher()[0]
            domain_info['version'] = ssl_sock.version()
            ssl_sock.close()
            return domain_info
        except ssl.SSLError:
            print('Failed to connect to ' + domain + ' ssl error.')
        except (TimeoutError, socket.timeout):
            print(domain + ' connection attempt failed due to timeout.')
        except socket.gaierror:
            print(domain + ' getaddrinfo failed.')
        except ConnectionRefusedError:
            print(domain + ' refused connection.')
        except ConnectionResetError:
            print(domain + ' connection forcibly closed.')

    def multiprocess_extraction(self, domains):
        """
        Uses Multiprocessing to quickly extract information 
        :param domains: List of Domains
        :return: JSON encoded object
        """
        pool = Pool(250)
        return json.dumps(pool.map(self.extract_data, domains))
