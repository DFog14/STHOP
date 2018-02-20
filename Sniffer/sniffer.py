import socket
from IPHeader import IP
import ssl

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.bind(("172.26.16.209", 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
try:
    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = IP(raw_buffer[0:20])
        print("IP Header")
        print(f"  |-Version                 : {ip_header.version}")
        print(f"  |-Header Length           : {ip_header.ihl}")
        print(f"  |-Type of Service         : {ip_header.tos}")
        print(f"  |-Total Length            : {ip_header.len}")
        print(f"  |-Identification          : {ip_header.id}")
        print(f"  |-Fragment Offset         : {ip_header.offset}")
        print(f"  |-Time to Live            : {ip_header.ttl}")
        print(f"  |-Protocol                : {ip_header.protocol_num}")
        print(f"  |-Header Checksum         : {ip_header.sum}");
        print(f"  |-Source IP Address       : {ip_header.src_address}")
        print(f"  |-Destination IP Address  : {ip_header.dst_address}")
except KeyboardInterrupt:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
