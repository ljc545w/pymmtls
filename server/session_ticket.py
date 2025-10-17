# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:41:16 2024

@author: Jack Li
"""
import time
from typing import List, Union
from .utility import get_random_key
from .const import (
    SESSION_TICKET_KEY,
    SESSION_TICKET_SHORT_LIFETIME,
    SESSION_TICKET_LONG_LIFETIME
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def _derive_aes_key_hkdf(master_key: bytes, nonce: bytes) -> bytes:
    """
    使用 HKDF(SHA256) 从 master_key 派生 16 字节 AES-GCM key(AES-128).
    这里把 nonce 作为 info, 以实现每票据不同的派生密钥。
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=nonce,
    )
    return hkdf.derive(master_key)

def ticket_encrypt(nonce, ticket_data) -> 'bytes':
    """
    加密序列化后的 ticket_data, 返回格式: ciphertext_with_tag
    使用 AES-GCM-128, 密钥通过 HKDF(master_key, info=nonce) 得到。
    """
    # 从全局 SESSION_TICKET_KEY 和 nonce 派生 16 字节 AES key
    aes_key = _derive_aes_key_hkdf(SESSION_TICKET_KEY, nonce)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, ticket_data, None)
    return ct

def ticket_decrypt(nonce, enc_ticket_data) -> 'bytes':
    """
    解密输入: ciphertext_with_tag, 返回明文 ticket bytes。
    解密失败会抛出异常（由调用方处理）。
    """
    if not enc_ticket_data or len(enc_ticket_data) < 16:
        # 至少要有: tag(16)
        raise ValueError("invalid encrypted ticket data")
    ct = enc_ticket_data
    aes_key = _derive_aes_key_hkdf(SESSION_TICKET_KEY, nonce)
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, None)


class Ticket:
    def __init__(self):
        self.timestamp: int = 0
        self.key: Union[bytes, None] = None
        self.age_add: Union[bytes, None] = None

    def serialize(self) -> 'bytes':
        result = bytearray()
        result.extend([0] * 4)
        result.extend(self.timestamp.to_bytes(4, 'big'))
        result.extend(len(self.key).to_bytes(2, 'big'))
        result.extend(self.key)
        result.extend(len(self.age_add).to_bytes(2, 'big'))
        result.extend(self.age_add)
        pkg_len = len(result) - 4
        result[0:4] = pkg_len.to_bytes(4, 'big')
        return bytes(result)

    @classmethod
    def create_ticket(cls, key: bytes, timestamp: int, age_add: bytes) -> 'Ticket':
        instance = cls()
        instance.timestamp = timestamp
        instance.key = key
        instance.age_add = age_add
        return instance


class SessionTicket:
    def __init__(self):
        self.ticket_type: int = 0
        self.ticket_life_time: int = 0
        self.ticket_age_add: Union[bytes, None] = None
        self.reserved: int = 0
        self.nonce: Union[bytes, None] = None
        self.ticket: Union[bytes, None] = None

    def serialize(self) -> 'bytes':
        result = bytearray()
        result.extend(self.ticket_type.to_bytes(1, 'big'))
        result.extend(self.ticket_life_time.to_bytes(4, 'big'))
        result.extend(len(self.ticket_age_add).to_bytes(2, 'big'))
        result.extend(self.ticket_age_add)
        result.extend(self.reserved.to_bytes(4, 'big'))
        result.extend(len(self.nonce).to_bytes(2, 'big'))
        result.extend(self.nonce)
        result.extend(len(self.ticket).to_bytes(2, 'big'))
        result.extend(self.ticket)
        return bytes(result)
    
    def parse_ticket(self) -> Union['Ticket', None]:
        try:
            assert self.nonce is not None and self.ticket is not None, "invalid session ticket data"
            ticket_data = ticket_decrypt(self.nonce, self.ticket)
            instance = Ticket()
            # skip package length
            ticket_data = ticket_data[4:]
            instance.timestamp = int.from_bytes(ticket_data[:4], 'big')
            ticket_data = ticket_data[4:]
            key_len = int.from_bytes(ticket_data[:2], 'big')
            ticket_data = ticket_data[2:]
            instance.key = ticket_data[:key_len]
            ticket_data = ticket_data[key_len:]
            add_len = int.from_bytes(ticket_data[:2], 'big')
            ticket_data = ticket_data[2:]
            instance.age_add = ticket_data[:add_len]
            assert (time.time() - instance.timestamp) <= self.ticket_life_time, "ticket expired"
            return instance
        except Exception:
            return None

    @classmethod
    def read_session_ticket(cls, data: bytes) -> 'SessionTicket':
        instance = cls()
        instance.ticket_type = data[0]
        data = data[1:]
        instance.ticket_life_time = int.from_bytes(data[:4], 'big')
        data = data[4:]

        length = int.from_bytes(data[:2], 'big')
        data = data[2:]
        instance.ticket_age_add = data[:length]
        data = data[length:]

        instance.reserved = int.from_bytes(data[:4], 'big')
        data = data[4:]

        length = int.from_bytes(data[:2], 'big')
        data = data[2:]
        instance.nonce = data[:length]
        data = data[length:]

        length = int.from_bytes(data[:2], 'big')
        data = data[2:]
        instance.ticket = data[:length]
        # data = data[length:]
        return instance

    @classmethod
    def create_session_ticket(cls, ticket_type: int, key: bytes, timestamp: int) -> 'SessionTicket':
        instance = cls()
        instance.ticket_type = ticket_type
        if ticket_type == 1:
            instance.nonce = get_random_key(12)
            instance.reserved = 72
            instance.ticket_age_add = b""
            instance.ticket_life_time = SESSION_TICKET_SHORT_LIFETIME
            ticket = Ticket.create_ticket(key, timestamp, instance.ticket_age_add)
            instance.ticket = ticket_encrypt(instance.nonce, ticket.serialize())
        elif ticket_type == 2:
            instance.nonce = get_random_key(12)
            instance.reserved = 72
            instance.ticket_age_add = get_random_key(32)
            instance.ticket_life_time = SESSION_TICKET_LONG_LIFETIME
            ticket = Ticket.create_ticket(key, timestamp, instance.ticket_age_add)
            instance.ticket = ticket_encrypt(instance.nonce, ticket.serialize())
        return instance


class NewSessionTicket:
    def __init__(self):
        self.reserved: int = 0
        self.count: int = 0
        self.tickets: List[SessionTicket] = []

    def serialize(self) -> 'bytes':
        result = bytearray()
        result.extend([0] * 4)
        result.append(0x4)
        result.append(len(self.tickets) & 0xff)
        for ticket in self.tickets:
            ticket_data = ticket.serialize()
            result.extend(len(ticket_data).to_bytes(4, 'big'))
            result.extend(ticket_data)
        d_len = len(result) - 4
        result[0:4] = d_len.to_bytes(4, 'big')
        return bytes(result)

    def export(self) -> 'bytes':
        result = bytearray()
        if len(self.tickets) == 0:
            return bytes(result)
        ticket_data = self.tickets[0].serialize()
        result.extend(len(ticket_data).to_bytes(4, 'big'))
        result.extend(ticket_data)
        return bytes(result)

    @classmethod
    def read_new_session_ticket(cls, data: bytes) -> 'NewSessionTicket':
        instance = cls()
        length = int.from_bytes(data[:4], 'big')
        assert length != 0
        data = data[4:]
        instance.reserved = data[0]
        data = data[1:]
        instance.count = data[0]
        data = data[1:]
        for i in range(instance.count):
            length = int.from_bytes(data[:4], 'big')
            data = data[4:]
            ticket_data = data[:length]
            data = data[length:]
            ticket = SessionTicket.read_session_ticket(ticket_data)
            instance.tickets.append(ticket)
        return instance

    @classmethod
    def create_new_session_ticket(cls, key: bytes, timestamp: int) -> 'NewSessionTicket':
        instance = cls()
        instance.count = 2
        instance.reserved = 4
        tickets = [SessionTicket.create_session_ticket(1, key, timestamp),
                   SessionTicket.create_session_ticket(2, key, timestamp)]
        instance.tickets = tickets
        return instance
