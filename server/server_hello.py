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
    
    @classmethod
    def new_pskone_hello(cls, server_mac: bytes, server_random: bytes) -> 'ServerHello':
        instance = cls()
        instance.protocol_version = ProtocolVersion
        cipher = TLS_PSK_WITH_AES_128_GCM_SHA256
        instance.cipher_suite = cipher
        instance.server_random = server_random
        extensions = {
            cipher: [server_mac],
        }
        instance.extensions = extensions
        return instance

    @classmethod
    def new_ecdhe_hello(cls, server_public_key: bytes) -> 'ServerHello':
        instance = cls()
        instance.protocol_version = ProtocolVersion
        cipher = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff
        instance.cipher_suite = cipher
        instance.server_random = get_random_key(32)
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
        result.extend(self.cipher_suite.to_bytes(2, "big"))
        result.extend(self.server_random)
        extensions_pos = len(result)
        result.extend([0] * 4)
        cipher_suite = self.cipher_suite
        if cipher_suite == TLS_PSK_WITH_AES_128_GCM_SHA256:
            result.append(len(self.extensions.keys()) & 0xff)
            psk_pos = len(result)
            result.extend([0x0] * 4)
            extension_type = 0xf
            result.extend(extension_type.to_bytes(2, "big"))
            key_pos = len(result)
            result.extend([0x0] * 4)
            extension = self.extensions[cipher_suite][0]
            result.extend(extension)
            key_len = len(result) - key_pos - 4
            result[key_pos: key_pos + 4] = key_len.to_bytes(4, 'big')
            psk_len = len(result) - psk_pos - 4
            result[psk_pos: psk_pos + 4] = psk_len.to_bytes(4, 'big')
        elif cipher_suite == (TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff):
            result.append((len(self.extensions.keys()) + 1) & 0xff)
            key_flag = 5
            extension_pos = len(result)
            result.extend([0] * 4)
            extension_type = 0x11
            result.extend(extension_type.to_bytes(2, "big"))
            result.extend(key_flag.to_bytes(4, "big"))
            key_flag += 1
            result.extend(len(self.extensions[cipher_suite][0]).to_bytes(2, "big"))
            result.extend(self.extensions[cipher_suite][0])
            extension_len = len(result) - extension_pos - 4
            result[extension_pos: extension_pos + 4] = extension_len.to_bytes(4, 'big')
            magic = [0x0, 0x13, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x3]
            result.extend(len(magic).to_bytes(4, "big"))
            result.extend(magic)
        else:
            raise RuntimeError(f"cipher ({cipher_suite}) not support")
        extensions_len = len(result) - extensions_pos - 4
        result[extensions_pos: extensions_pos + 4] = extensions_len.to_bytes(4, 'big')
        pack_len = len(result) - 4
        result[:4] = pack_len.to_bytes(4, 'big')
        return bytes(result)
