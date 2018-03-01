#! /usr/bin/env python3

import json
import random
import socket
import struct

num_packets = input('How many random packets do you require?\n')

ciphersuites = ["DHE-RSA-AES256-GCM-SHA384","DHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-SHA256", "DHE-RSA-AES128-SHA256", "ECDHE-RSA-AES256-SHA384", "ECDHE-RSA-AES128-SHA256", "ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA", "AES256-GCM-SHA384", "AES128-GCM-SHA256", "AES256-SHA256", "AES128-SHA256", "AES256-SHA", "AES128-SHA", "DES-CBC3-SHA", "DHE-RSA-AES256-SHA", "DHE-RSA-AES128-SHA"];
tls_versions = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "SSLv1.0", "SSLv2.0", "SSLv3.0"];

def random_packets():
    print("The number of packets you requested:", num_packets,"\n")
    print("The TLS version of the packet: ", random.choice(tls_versions),"\n")    
    print("The ciphersuite of the packet: ", random.choice(ciphersuites),"\n")
    ipv4 = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)));
    print("The IP of the packet: ", ipv4,"\n")
    

def packet():
    ipv4 = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)));
    new_data = {}
    new_data[''] = []
    for i in range(0,int(num_packets)):
        domain = "fake"+str(i)+".com";
    #new_data = {}
    #new_data[''] = []
        new_data[''].append({"domain": domain, "ip_address": ipv4, "ciphersuite:" :"", "version": random.choice(tls_versions), "ciphersuite:" : random.choice(ciphersuites)})
    
    with open('new_data.json','w') as outfile:
        json.dump(new_data, outfile)

for i in range(0,int(num_packets)):
    random_packets()
packet()