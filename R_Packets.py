"""""""""""""""""""""""""""""""""""""Random Packets Generator"""""""""""""""""""""""""""""""""
#! /usr/bin/env python3

""" The purpose of this python script is to generate random packets for the verification and flagging of the Malicious Traffic """

import json
import random
import socket
import struct
import dpkt
import csv
from scapy.all import *
import binascii

# Requesting the number of packets required to be created later. 

num_packets = input('How many random packets do you require?\n')

# List of most commonly used TLS or SSL

tls_versions = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "SSLv1.0", "SSLv2.0", "SSLv3.0"];

# List of most commonly used Ciphers for each version

cipher_tlsv0 = ["NULL-MD5","NULL-SHA","EXP-RC4-MD5","RC4-MD5","RC4-SHA","EXP-RC2-CBC-MD5","IDEA-CBC-SHA","EXP-DES-CBC-SHA","DES-CBC-SHA","DES-CBC3-SHA","EXP-DHE-DSS-DES-CBC-SHA","DHE-DSS-CBC-SHA","DHE-DSS-DES-CBC3-SHA","EXP-DHE-RSA-DES-CBC-SHA","DHE-RSA-DES-CBC-SHA","DHE-RSA-DES-CBC3-SHA","EXP-ADH-RC4-MD5","ADH-RC4-MD5","EXP-ADH-DES-CBC-SHA","ADH-DES-CBC-SHA","ADH-DES-CBC3-SHA","AES128-SHA","AES256-SHA","DH-DSS-AES128-SHA","DH-DSS-AES256-SHA","DH-RSA-AES128-SHA","DH-RSA-AES256-SHA","DHE-DSS-AES128-SHA","DHE-DSS-AES256-SHA","DHE-RSA-AES128-SHA","DHE-RSA-AES256-SHA","ADH-AES128-SHA","ADH-AES256-SHA","CAMELLIA128-SHA","CAMELLIA256-SHA","DH-DSS-CAMELLIA128-SHA","DH-DSS-CAMELLIA256-SHA","DH-RSA-CAMELLIA128-SHA","DH-RSA-CAMELLIA256-SHA","DHE-DSS-CAMELLIA128-SHA","DHE-DSS-CAMELLIA256-SHA","DHE-RSA-CAMELLIA128-SHA","DHE-RSA-CAMELLIA256-SHA","ADH-CAMELLIA128-SHA","ADH-CAMELLIA256-SHA","SEED-SHA","DH-DSS-SEED-SHA","DH-RSA-SEED-SHA","DHE-DSS-SEED-SHA","DHE-RSA-SEED-SHA","ADH-SEED-SHA","GOST94-GOST89-GOST89","GOST2001-GOST89-GOST89","GOST94-NULL-GOST94","GOST2001-NULL-GOST94","EXP1024-DES-CBC-SHA","EXP1024-RC4-SHA","EXP1024-DHE-DSS-DES-CBC-SHA","EXP1024-DHE-DSS-RC4-SHA","DHE-DSS-RC4-SHA","ECDH-RSA-NULL-SHA","ECDH-RSA-RC4-SHA","ECDH-RSA-DES-CBC3-SHA","ECDH-RSA-AES128-SHA","ECDH-RSA-AES256-SHA","ECDH-ECDSA-NULL-SHA","ECDH-ECDSA-RC4-SHA","ECDH-ECDSA-DES-CBC3-SHA","ECDH-ECDSA-AES128-SHA","ECDH-ECDSA-AES256-SHA","ECDHE-RSA-NULL-SHA","ECDHE-RSA-RC4-SHA","ECDHE-RSA-DES-CBC3-SHA","ECDHE-RSA-AES128-SHA","ECDHE-RSA-AES256-SHA","ECDHE-ECDSA-NULL-SHA","ECDHE-ECDSA-RC4-SHA","ECDHE-ECDSA-DES-CBC3-SHA","ECDHE-ECDSA-AES128-SHA","ECDHE-ECDSA-AES256-SHA","AECDH-NULL-SHA","AECDH-RC4-SHA","AECDH-DES-CBC3-SHA","AECDH-AES128-SHA","AECDH-AES256-SHA"];
cipher_tlsv1 = ["NULL-SHA256","AES128-SHA256","AES256-SHA256","AES128-GCM-SHA256","AES256-GCM-SHA384","DH-RSA-AES128-SHA256","DH-RSA-AES256-SHA256","DH-RSA-AES128-GCM-SHA256","DH-RSA-AES256-GCM-SHA384","DH-DSS-AES128-SHA256","DH-DSS-AES256-SHA256","DH-DSS-AES128-GCM-SHA256","DH-DSS-AES256-GCM-SHA384","DHE-RSA-AES128-SHA256","DHE-RSA-AES256-SHA256","DHE-RSA-AES128-GCM-SHA256","DHE-RSA-AES256-GCM-SHA384","DHE-DSS-AES128-SHA256","DHE-DSS-AES256-SHA256","DHE-DSS-AES128-GCM-SHA256","DHE-DSS-AES256-GCM-SHA384","ECDH-RSA-AES128-SHA256","ECDH-RSA-AES256-SHA384","ECDH-RSA-AES128-GCM-SHA256","ECDH-RSA-AES256-GCM-SHA384","ECDH-ECDSA-AES128-SHA256","ECDH-ECDSA-AES256-SHA384","ECDH-ECDSA-AES128-GCM-SHA256","ECDH-ECDSA-AES256-GCM-SHA384","ECDHE-RSA-AES128-SHA256","ECDHE-RSA-AES256-SHA384","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-RSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-SHA256","ECDHE-ECDSA-AES256-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","ADH-AES128-SHA256","ADH-AES256-SHA256","ADH-AES128-GCM-SHA256","ADH-AES256-GCM-SHA384","ECDHE-ECDSA-CAMELLIA128-SHA256","ECDHE-ECDSA-CAMELLIA256-SHA384","ECDH-ECDSA-CAMELLIA128-SHA256","ECDH-ECDSA-CAMELLIA256-SHA384","ECDHE-RSA-CAMELLIA128-SHA256","ECDHE-RSA-CAMELLIA256-SHA384","ECDH-RSA-CAMELLIA128-SHA256","ECDH-RSA-CAMELLIA256-SHA384"];
cipher_tlsv2 = ["NULL-SHA256","AES128-SHA256","AES256-SHA256","AES128-GCM-SHA256","AES256-GCM-SHA384","DH-RSA-AES128-SHA256","DH-RSA-AES256-SHA256","DH-RSA-AES128-GCM-SHA256","DH-RSA-AES256-GCM-SHA384","DH-DSS-AES128-SHA256","DH-DSS-AES256-SHA256","DH-DSS-AES128-GCM-SHA256","DH-DSS-AES256-GCM-SHA384","DHE-RSA-AES128-SHA256","DHE-RSA-AES256-SHA256","DHE-RSA-AES128-GCM-SHA256","DHE-RSA-AES256-GCM-SHA384","DHE-DSS-AES128-SHA256","DHE-DSS-AES256-SHA256","DHE-DSS-AES128-GCM-SHA256","DHE-DSS-AES256-GCM-SHA384","ECDH-RSA-AES128-SHA256","ECDH-RSA-AES256-SHA384","ECDH-RSA-AES128-GCM-SHA256","ECDH-RSA-AES256-GCM-SHA384","ECDH-ECDSA-AES128-SHA256","ECDH-ECDSA-AES256-SHA384","ECDH-ECDSA-AES128-GCM-SHA256","ECDH-ECDSA-AES256-GCM-SHA384","ECDHE-RSA-AES128-SHA256","ECDHE-RSA-AES256-SHA384","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-RSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-SHA256","ECDHE-ECDSA-AES256-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","ADH-AES128-SHA256","ADH-AES256-SHA256","ADH-AES128-GCM-SHA256","ADH-AES256-GCM-SHA384","ECDHE-ECDSA-CAMELLIA128-SHA256","ECDHE-ECDSA-CAMELLIA256-SHA384","ECDH-ECDSA-CAMELLIA128-SHA256","ECDH-ECDSA-CAMELLIA256-SHA384","ECDHE-RSA-CAMELLIA128-SHA256","ECDHE-RSA-CAMELLIA256-SHA384","ECDH-RSA-CAMELLIA128-SHA256","ECDH-RSA-CAMELLIA256-SHA384"];
cipher_sslv1 = ["NONE FOUND"];
cipher_sslv2 = ["RC4-MD5","EXP-RC4-MD5","RC2-MD5","EXP-RC2-MD5","IDEA-CBC-MD5","DES-CBC-MD5","DES-CBC3-MD5"];
cipher_sslv3 = ["NULL-MD5","NULL-SHA","EXP-RC4-MD5","RC4-MD5","RC4-SHA","EXP-RC2-CBC-MD5","IDEA-CBC-SHA","EXP-DES-CBC-SHA","DES-CBC-SHA","DES-CBC3-SHA","EXP-EDH-DSS-DES-CBC-SHA","EDH-DSS-CBC-SHA","EDH-DSS-DES-CBC3-SHA","EXP-EDH-RSA-DES-CBC-SHA","EDH-RSA-DES-CBC-SHA","EDH-RSA-DES-CBC3-SHA","EXP-ADH-RC4-MD5","ADH-RC4-MD5","EXP-ADH-DES-CBC-SHA","ADH-DES-CBC-SHA","ADH-DES-CBC3-SHA","DHE-DSS-RC4-SHA"];

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
    #packets = rdpcap('new_data.pcap')
    #packets.show()
    ipv4 = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)));
    #new_data = {}
    new_data = []
    for i in range(0,int(num_packets)):
        domain = "fake"+str(i)+".com";
        ipv4 = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)));
    #new_data = {}
    #new_data[''] = []
        tls = random.choice(tls_versions);
        if tls == "TLSv1.0":
            cipher = random.choice(cipher_tlsv0);
            new_data.append({"domain": domain, "ip_address": ipv4, "version": tls, "ciphersuite" : cipher})
        elif tls == "TLSv1.1":
            cipher = random.choice(cipher_tlsv1);
            new_data.append({"domain": domain, "ip_address": ipv4, "version": tls, "ciphersuite" : cipher})
        elif tls == "TLSv1.2":
            cipher = random.choice(cipher_tlsv2);
            new_data.append({"domain": domain, "ip_address": ipv4, "version": tls, "ciphersuite" : cipher})
        elif tls == "SSLv1.0":
            cipher = random.choice(cipher_sslv1);
            new_data.append({"domain": domain, "ip_address": ipv4, "version": tls, "ciphersuite" : cipher})
        elif tls == "SSLv2.0":
            cipher = random.choice(cipher_sslv2);
            new_data.append({"domain": domain, "ip_address": ipv4, "version": tls, "ciphersuite" : cipher})
        elif tls == "SSLv3.0":
            cipher = random.choice(cipher_sslv3);
            new_data.append({"domain": domain, "ip_address": ipv4, "version": tls, "ciphersuite" : cipher}) 
        
        #S = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(ipv4)/TCP(tls)/("%s",domain)
        #wrpcap('random.pcap',hexdump(S), append=True)
        #strings = [str(x).encode('utf-8') for x in new_data]
        #with open('random.pcap','w') as outfile:
            #json.dump(strings, outfile, indent = 0)
        A = hexdump(str(new_data))
        #wrpcap('random.pcap', A, append = True)
    return A[num_packets] #Uncomment if want to use cap() function

""" Section Name : Function to Generate PCAP file """""""""""""""""""""""""""""""""""""""""

def cap():
    strings = text2pcap(json_packets())
    wrpcap('random.pcap',strings, append = True)

""" Section Name : Random Packets PCAP """""""""""""""""""""""""""""""""""""""""""""""""""""

""" Below Section provides the code for the generation of the pcap file, which is also used to verify that the data dump works on the generated data. """

""" Attempt Using DPKT """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""
def pcap_packets(): 
    ipv4 = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)));
    new_data = {}
    new_data[''] = []
    for i in range(0,int(num_packets)):
        domain = "fake"+str(i)+".com";
        ipv4 = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)));


    outfilepcap = open('new_data.pcap', 'wb')
    writer = dpkt.pcap.Writer(outfilepcap)
"""

""" Main Function """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
def main():
    #json_packets()
    #for i in range(0,int(num_packets)):
        #randome_packets()
    #pcap_packets()
    cap()
""" Running the Script """
main()

""""""""""""""""""""""""""""""""""""" Termination Point """""""""""""""""""""""""""""""""""""
