#!/usr/bin/env python 3
from HandshakeHelper import HandshakeHelper
import time

def main():
    handshake_helper = HandshakeHelper()
    domains = handshake_helper.domain_reader("data/sites_10k.txt")
    return handshake_helper.multiprocess_extraction(domains)

if __name__ == '__main__':
    start = time.time()
    test = main()
    print("Took %s seconds to Execute" % (time.time()-start))
    with open('output.txt', 'w') as file:
        file.write(test)
