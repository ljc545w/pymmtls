# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:40:43 2024

@author: Jack Li
"""

from .const import (
    ProtocolVersion,
    TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_PSK_WITH_AES_128_GCM_SHA256
)
from typing import Dict, List, Union
from .utility import get_random_key


class ServerHello:
    def __init__(self):
        self.protocol_version: int = 0
        self.cipher: int = 0
        self.public_key: Union[bytes, None] = None
        self.random: Union[bytes, None] = None
        self.extensions: Union[Dict[int, List[bytes]], None] = None
        
    @classmethod
    def read_server_hello(cls, data: bytes) -> 'ServerHello':
        pack_len = int.from_bytes(data[:4], "big")
        if len(data) != (pack_len + 4):
            raise RuntimeError("data corrupted")
        data = data[4:]
        # skip flag
        data = data[1:]
        protocol_version = int.from_bytes(data[:2], "little")
        data = data[2:]
        cipher = int.from_bytes(data[:2], "big")
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
        key_len = int.from_bytes(data[:2], "big")
        data = data[2:]
        ec_point = data[:key_len]
        # data = data[ken_len:]
        instance = cls()
        instance.protocol_version = protocol_version
        instance.cipher = cipher
        instance.public_key = ec_point
        return instance

    @classmethod
    def new_ecdh_hello(cls, server_public_key: bytes) -> 'ServerHello':
        instance = cls()
        instance.protocol_version = ProtocolVersion
        cipher = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff
        instance.cipher = cipher
        instance.random = get_random_key(32)
        instance.public_key = server_public_key
        extensions = {
            cipher: [server_public_key],
        }
        instance.extensions = extensions
        return instance

    def serialize(self) -> bytes:
        result = bytearray()
        result.extend([0] * 4)
        # flag
        result.append(0x2)
        result.extend(self.protocol_version.to_bytes(2, "little"))
        result.extend(self.cipher.to_bytes(2, "big"))
        result.extend(self.random)
        extensions_pos = len(result)
        result.extend([0] * 4)
        result.append(len(self.extensions.keys()) & 0xff)
        cipher = self.cipher
        if cipher == TLS_PSK_WITH_AES_128_GCM_SHA256:
            psk_pos = len(result)
            result.extend([0x0] * 4)
            extension_type = 0xf
            result.extend(extension_type.to_bytes(2, "big"))
            result.append(0x1)
            key_pos = len(result)
            result.extend([0x0] * 4)
            extension = self.extensions[cipher][0]
            result.extend(extension)
            key_len = len(result) - key_pos - 4
            result[key_pos: key_pos + 4] = key_len.to_bytes(4, 'big')
            psk_len = len(result) - psk_pos - 4
            result[psk_pos: psk_pos + 4] = psk_len.to_bytes(4, 'big')
        elif cipher == (TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff):
            key_flag = 5
            extension_pos = len(result)
            result.extend([0] * 4)
            extension_type = 0x11
            result.extend(extension_type.to_bytes(2, "big"))
            result.extend(key_flag.to_bytes(4, "big"))
            key_flag += 1
            result.extend(len(self.extensions[cipher][0]).to_bytes(2, "big"))
            result.extend(self.extensions[cipher][0])
            extension_len = len(result) - extension_pos - 4
            result[extension_pos: extension_pos + 4] = extension_len.to_bytes(4, 'big')
            magic = [0x0, 0x13, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x3]
            result.extend(len(magic).to_bytes(4, "big"))
            result.extend(magic)
        else:
            raise RuntimeError(f"cipher ({cipher}) not support")
        extensions_len = len(result) - extensions_pos - 4
        result[extensions_pos: extensions_pos + 4] = extensions_len.to_bytes(4, 'big')
        pack_len = len(result) - 4
        result[:4] = pack_len.to_bytes(4, 'big')
        return bytes(result)
