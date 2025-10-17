# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:40:43 2024

@author: Jack Li
"""
from typing import Dict, List, Union
from .const import (
    TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_PSK_WITH_AES_128_GCM_SHA256
)


class ServerHello:
    def __init__(self):
        self.protocol_version: int = 0
        self.cipher_suite: int = 0
        self.server_random: Union[bytes, None] = None
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
        extensions = {cipher_suite: []}
        if cipher_suite == (TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff):
            for i in range(ext_count):
                # extension package length
                ext_pkg_len = int.from_bytes(data[:4], "big")
                data = data[4:]
                # extension type
                ext_type = int.from_bytes(data[:2], "big")
                data = data[2:]
                # server public key extension
                if ext_type == 0x11:
                    # skip extension key flag, 0x05
                    data = data[4:]
                    ext_len = int.from_bytes(data[:2], "big")
                    data = data[2:]
                    ext = data[:ext_len]
                    extensions[cipher_suite].append(ext)
                    data = data[ext_len:]
                # magic extension
                elif ext_type == 0x13:
                    magic = data[:ext_pkg_len - 2]
                    data = data[ext_pkg_len - 2:]
                    magic_num1 = int.from_bytes(magic[:4], "big")
                    magic_num2 = int.from_bytes(magic[4:], "big")
                    assert (magic_num1 == 1 and magic_num2 == 3), "magic extension corrupted"
                else:
                    data = data[ext_pkg_len:]
        elif cipher_suite == TLS_PSK_WITH_AES_128_GCM_SHA256:
            # extension package length
            ext_pkg_len = int.from_bytes(data[:4], "big")
            data = data[4:]
            # extension type
            ext_type = int.from_bytes(data[:2], "big")
            data = data[2:]
            ext_len = int.from_bytes(data[:4], "big")
            data = data[4:]
            ext = data[:ext_len]
            extensions[cipher_suite].append(ext)
            data = data[ext_len:]
        else:
            raise RuntimeError(f"unsupport cipher suite {cipher_suite}")
        instance = cls()
        instance.protocol_version = protocol_version
        instance.cipher_suite = cipher_suite
        instance.server_random = server_random
        instance.extensions = extensions
        return instance
