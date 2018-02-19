#!/usr/bin/env python 3
from HandshakeHelper import HandshakeHelper
import time

def main():
    handshake_helper = HandshakeHelper()
    domains = handshake_helper.domain_reader("data/malicious_domains.txt")
    return handshake_helper.multiprocess_extraction(domains[:10000])

if __name__ == '__main__':
    start = time.time()
    test = main()
    print("Took %s seconds to Execute" % (time.time()-start))
    with open('malicious_output.json', 'w') as file:
        file.write(test)
