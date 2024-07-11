# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:38:31 2024

@author: Jack Li
"""

from .const import (
    ProtocolVersion,
    TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_PSK_WITH_AES_128_GCM_SHA256
)
from . import utility
import time
from .session_ticket import SessionTicket
from typing import List, Dict


class ClientHello:
    def __init__(self):
        self.protocol_version: int = 0
        self.cipher_suites: List[int] = []
        self.random: bytes or None = None
        self.timestamp: int = 0
        self.extensions: Dict[int, List[bytes]] or None = None

    @classmethod
    def new_ecdh_hello(cls,
                       client_public_key: bytes,
                       client_verify_key: bytes) -> 'ClientHello':
        instance = cls()
        instance.protocol_version = ProtocolVersion
        instance.timestamp = int(time.time())
        instance.random = utility.get_random_key(32)
        cipher_suites = []
        extensions = {}
        cipher_suites.append(TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff)
        extensions[TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff] = [
            client_public_key,
            client_verify_key
        ]
        instance.cipher_suites = cipher_suites
        instance.extensions = extensions
        return instance

    @classmethod
    def new_pskone_hello(cls,
                         client_public_key: bytes,
                         client_verify_key: bytes,
                         session_ticket: 'SessionTicket') -> 'ClientHello':
        instance = cls()
        instance.protocol_version = ProtocolVersion
        instance.timestamp = int(time.time())
        instance.random = utility.get_random_key(32)
        cipher_suites = []
        extensions = {}
        cipher_suites.append(TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff)
        cipher_suites.append(TLS_PSK_WITH_AES_128_GCM_SHA256)
        session_ticket.ticket_age_add = b""
        ticket_data = session_ticket.serialize()
        extensions[TLS_PSK_WITH_AES_128_GCM_SHA256] = [ticket_data]
        extensions[TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff] = [
            client_public_key,
            client_verify_key
        ]
        instance.cipher_suites = cipher_suites
        instance.extensions = extensions
        return instance

    @classmethod
    def new_pskzero_hello(cls, session_ticket: 'SessionTicket') -> 'ClientHello':
        instance = cls()
        instance.protocol_version = ProtocolVersion
        instance.timestamp = int(time.time())
        instance.random = utility.get_random_key(32)
        cipher_suites = []
        extensions = {}
        cipher_suites.append(TLS_PSK_WITH_AES_128_GCM_SHA256)
        ticket_data = session_ticket.serialize()
        extensions[TLS_PSK_WITH_AES_128_GCM_SHA256] = [ticket_data]
        instance.cipher_suites = cipher_suites
        instance.extensions = extensions
        return instance

    def serialize(self) -> bytes:
        result = bytearray()
        result.extend([0x0] * 4)
        result.append(0x1)
        result.extend(self.protocol_version.to_bytes(2, 'little'))
        result.append(len(self.cipher_suites))
        for cipherSuite in self.cipher_suites:
            result.extend(cipherSuite.to_bytes(2, 'big'))
        result.extend(self.random)
        result.extend(self.timestamp.to_bytes(4, 'big'))
        cipher_pos = len(result)
        result.extend([0x0] * 4)
        result.append(len(self.cipher_suites) & 0xff)
        for si in range(len(self.cipher_suites), 0, -1):
            cipher = self.cipher_suites[si - 1]
            if cipher == TLS_PSK_WITH_AES_128_GCM_SHA256:
                psk_pos = len(result)
                result.extend([0x0] * 4)
                result.append(0x0)
                result.append(0xf)
                result.append(0x1)
                key_pos = len(result)
                result.extend([0x0] * 4)
                extension = self.extensions[cipher][0]
                result.extend(extension)
                ken_len = len(result) - key_pos - 4
                result[key_pos: key_pos + 4] = ken_len.to_bytes(4, 'big')
                psk_len = len(result) - psk_pos - 4
                result[psk_pos: psk_pos + 4] = psk_len.to_bytes(4, 'big')
            elif cipher == (TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 & 0xffff):
                ecdsa_pos = len(result)
                result.extend([0x0] * 4)
                result.append(0x0)
                result.append(0x10)
                result.append(len(self.extensions[cipher]) & 0xff)
                key_flag = 5
                for extension in self.extensions[cipher]:
                    key_pos = len(result)
                    result.extend([0x0] * 4)
                    result.extend(key_flag.to_bytes(4, 'big'))
                    key_flag += 1
                    result.extend(len(extension).to_bytes(2, 'big'))
                    result.extend(extension)
                    ken_len = len(result) - key_pos - 4
                    result[key_pos: key_pos + 4] = ken_len.to_bytes(4, 'big')
                magic = [0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04]
                result.extend(magic)
                ecdsa_len = len(result) - ecdsa_pos - 4
                result[ecdsa_pos: ecdsa_pos + 4] = ecdsa_len.to_bytes(4, 'big')
            else:
                raise RuntimeError(f"cipher ({cipher}) not support")
        cipher_len = len(result) - cipher_pos - 4
        result[cipher_pos: cipher_pos + 4] = cipher_len.to_bytes(4, 'big')
        total_len = len(result) - 4
        result[0:4] = total_len.to_bytes(4, 'big')
        return bytes(result)