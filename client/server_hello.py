# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:40:43 2024

@author: Jack Li
"""


class ServerHello:
    def __init__(self):
        self.protocol_version: int = 0
        self.cipher_suites: int = 0
        self.public_key: bytes or None = None
        
    @classmethod
    def read_server_hello(cls, data: bytes) -> 'ServerHello':
        pack_len = int.from_bytes(data[:4], "big")
        if len(data) != (pack_len + 4):
            raise RuntimeError("data corrupted")
        data = data[4:]
        # skip flag, 0x02
        data = data[1:]
        protocol_version = int.from_bytes(data[:2], "little")
        data = data[2:]
        cipher_suites = int.from_bytes(data[:2], "big")
        data = data[2:]
        # skip server random
        data = data[32:]
        # skip extensions package length
        data = data[4:]
        # skip extensions count
        data = data[1:]
        # skip extension package length
        data = data[4:]
        # skip extension type
        data = data[2:]
        # skip extension array index
        data = data[4:]
        ken_len = int.from_bytes(data[:2], "big")
        data = data[2:]
        ec_point = data[:ken_len]
        # data = data[ken_len:]
        instance = cls()
        instance.protocol_version = protocol_version
        instance.cipher_suites = cipher_suites
        instance.public_key = ec_point
        return instance
