import socket
from IPHeader import IP
import ssl

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
"""
sock = ssl.wrap_socket(sniffer)

sock.connect(("www.google.com", 443))
sock.send(b'GET / HTTP/1.1\n')
data=sock.recv(1280)
byte_data = bytearray()
byte_data.extend(data)
print(byte_data)
sock.close()
"""
sniffer.connect(("www.googl.com", 443))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
#sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
try:
    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = IP(raw_buffer[0:20])
        print(f"Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")
        print(f"{ip_header.version}")
except KeyboardInterrupt:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
