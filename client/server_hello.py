# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:40:43 2024

@author: Jack Li
"""
from typing import Dict, List, Union


class ServerHello:
    def __init__(self):
        self.protocol_version: int = 0
        self.cipher_suite: int = 0
        self.server_random: Union[bytearray, None] = None
        self.extensions: Union[Dict[int, List[bytes]], None] = None
        
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
        cipher_suite = int.from_bytes(data[:2], "big")
        data = data[2:]
        # server random
        server_random = data[:32]
        data = data[32:]
        # skip extensions package length
        data = data[4:]
        # extensions count
        ext_count = data[0]
        data = data[1:]
        extensions = {}
        for i in range(ext_count):
            # skip extension package length
            data = data[4:]
            # extension type
            ext_type = int.from_bytes(data[:2], "big")
            if ext_type not in extensions:
                extensions[ext_type] = []
            data = data[2:]
            # skip extension array index
            data = data[4:]
            ext_len = int.from_bytes(data[:2], "big")
            data = data[2:]
            ext = data[:ext_len]
            extensions[ext_type].append(ext)
            data = data[ext_len:]
        instance = cls()
        instance.protocol_version = protocol_version
        instance.cipher_suite = cipher_suite
        instance.server_random = bytearray(server_random)
        instance.extensions = extensions
        return instance
