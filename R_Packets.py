"""""""""""""""""""""""""""""""""""""Random Packets Generator"""""""""""""""""""""""""""""""""
#! /usr/bin/env python3

""" The purpose of this python script is to generate random packets for the verification and flagging of the Malicious Traffic """

import json
import random
import socket
import struct
import dpkt

# Requesting the number of packets required to be created later. 

num_packets = input('How many random packets do you require?\n')

# List of most commonly used ciphersuites

ciphersuites = ["DHE-RSA-AES256-GCM-SHA384","DHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-SHA256", "DHE-RSA-AES128-SHA256", "ECDHE-RSA-AES256-SHA384", "ECDHE-RSA-AES128-SHA256", "ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA", "AES256-GCM-SHA384", "AES128-GCM-SHA256", "AES256-SHA256", "AES128-SHA256", "AES256-SHA", "AES128-SHA", "DES-CBC3-SHA", "DHE-RSA-AES256-SHA", "DHE-RSA-AES128-SHA"];

# List of most commonly used TLS or SSL

tls_versions = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "SSLv1.0", "SSLv2.0", "SSLv3.0"];

""" Section Name : Random Packets Prinout """""""""""""""""""""""""""""""""""""""""""""""""""

""" Below Section which is commented out was used to verify that each part of the package generation had actually worked or not. """

"""
def random_packets():
    print("The number of packets you requested:", num_packets,"\n")
    print("The TLS version of the packet: ", random.choice(tls_versions),"\n")    
    print("The ciphersuite of the packet: ", random.choice(ciphersuites),"\n")
    ipv4 = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)));
    print("The IP of the packet: ", ipv4,"\n")
"""

""" Section Name : Random Packets JSON """""""""""""""""""""""""""""""""""""""""""""""""""""

""" Below Section provides the code for the generation of the json file, which is also used to verify that the data dump works on the generated data. """

def json_packets():
    ipv4 = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)));
    new_data = {}
    new_data[''] = []
    for i in range(0,int(num_packets)):
        domain = "fake"+str(i)+".com";
        ipv4 = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)));
    #new_data = {}
    #new_data[''] = []
        new_data[''].append({"domain": domain, "ip_address": ipv4, "ciphersuite:" :"", "version": random.choice(tls_versions), "ciphersuite:" : random.choice(ciphersuites)})
    
    with open('new_data.json','w') as outfile:
        json.dump(new_data, outfile, indent = 0)

""" Section Name : Random Packets PCAP """""""""""""""""""""""""""""""""""""""""""""""""""""

""" Below Section provides the code for the generation of the pcap file, which is also used to verify that the data dump works on the generated data. """

def pcap_packets():
    infilepcap = open('original.pcap','rb')
    reader = dpkt.pcap.Reader(infilepcap)

    outfilepcap = open('new_data.pcap', 'wb')
    writer = dpkt.pcap.Writer(outfilepcap)

""" Main Function """
def main():
    json_packets()
    #for i in range(0,int(num_packets)):
        #randome_packets()
""" Running the Script """
main()

""""""""""""""""""""""""""""""""""""" Termination Point """""""""""""""""""""""""""""""""""""
