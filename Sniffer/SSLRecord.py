import socket
import struct
from ctypes import *

class SSLRecord(Structure):
    _fields_ = [
            ("record_type",    c_ubyte, 4),
            ("version", c_ushort),
            ("len_data_in_record",     c_ushort),
            ("handshake_type", c_byte),
            ("len_data_follow_record",  c_ushort),
            ("data", c_ulong)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.record_type = {
                20: "SSL3_RT_CHANGE_CIPHER_SPEC",
                21: "SSL_RT_ALERT",
                22: "SSL_RT_HANDSHAKE",
                23: "SSL3_RT_APPLICATION_DATA"
        }

        self.ssl_version = {

        }

        self.handshake_type = {
                0: "SSL3_MT_HELLO_REQUEST",
                1: "SSL3_MT_CLIENT_HELLO",
                2: "SSL3_MT_SERVER_HELLO",
                11: "SSL3_MT_CERTIFICATE",
                12: "SSL3_MT_SERVER_KEY_EXCHANGE",
                13: "SSL3_MT_CERTIFICATE_REQUEST",
                14: "SSL3_MT_SERVER_DONE",
                15: "SSL3_MT_CERTIFICATE_VERIFY",
                16: "SSL3_MT_CLIENT_KEY_EXCHANGE",
                20: "SSL3_MT_FINISHED"
        }


