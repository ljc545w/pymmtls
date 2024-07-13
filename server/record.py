# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:40:23 2024

@author: Jack Li
"""

from .const import (
    MagicAbort,
    MagicHandshake,
    MagicRecord,
    MagicSystem,
    ProtocolVersion
    )
from .utility import xor_nonce
from .session import TrafficKeyPair
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


class DataRecord:
    def __init__(self, 
                 data_type: int,
                 seq: int,
                 data: bytes):
        self.data_type = data_type
        self.seq = seq
        self.data = data

    @classmethod
    def read_data_record(cls, data: bytes) -> 'DataRecord':
        # length = int.from_bytes(data[:4], "big")
        data = data[4:]
        data = data[2:]
        data = data[2:]
        data_type = int.from_bytes(data[:4], "big")
        data = data[4:]
        seq = int.from_bytes(data[:4], "big")
        data = data[4:]
        return cls(data_type, seq, data)
        
    def serialize(self) -> bytes:
        result = bytearray()
        length = len(self.data) + 16
        result.extend(length.to_bytes(4, "big"))
        result.extend([0x0, 0x10])
        result.extend([0x0, 0x1])
        result.extend(self.data_type.to_bytes(4, "big"))
        result.extend(self.seq.to_bytes(4, "big"))
        result.extend(self.data)
        return bytes(result)


class MMTLSRecord:
    def __init__(self):
        self.record_type: int = 0
        self.version: int = 0
        self.length: int = 0
        self.data: bytes or None = None
        
    @classmethod
    def create_abort_record(cls, data: bytes) -> 'MMTLSRecord':
        return cls.create_record(MagicAbort, data)
    
    @classmethod
    def create_handshake_record(cls, data: bytes) -> 'MMTLSRecord':
        return cls.create_record(MagicHandshake, data)
    
    @classmethod
    def create_data_record(cls, 
                           data_type: int, 
                           seq: int, 
                           data: bytes) -> 'MMTLSRecord':
        data_record = DataRecord(data_type, seq, data)
        return cls.create_record(MagicRecord, data_record.serialize())
    
    @classmethod
    def create_raw_data_record(cls, data: bytes) -> 'MMTLSRecord':
        return cls.create_record(MagicRecord, data)
    
    @classmethod
    def create_system_record(cls, data: bytes) -> 'MMTLSRecord':
        return cls.create_record(MagicSystem, data)
        
    @classmethod
    def create_record(cls, 
                      record_type: int, 
                      data: bytes) -> 'MMTLSRecord':
        instance = cls()
        instance.record_type = record_type
        instance.version = ProtocolVersion
        instance.length = len(data) & 0xffff
        instance.data = data
        return instance
    
    @classmethod
    def read_record(cls, 
                    data: bytes) -> 'MMTLSRecord':
        instance = cls()
        instance.record_type = data[0]
        instance.version = (data[1] << 8) | data[2]
        length = (data[3] << 8) | data[4]
        instance.length = length
        instance.data = data[5:5+length]
        return instance
    
    def serialize(self) -> bytes:
        result = bytearray()
        result.extend(self.record_type.to_bytes(1, "big"))
        result.extend(self.version.to_bytes(2, "big"))
        result.extend(self.length.to_bytes(2, "big"))
        result.extend(self.data)
        return bytes(result)
    
    def encrypt(self, keys: 'TrafficKeyPair', server_seq_num: int) -> int:
        nonce = keys.server_nonce
        if len(nonce) == 0:
            return -1
        nonce = xor_nonce(nonce, server_seq_num)
        auddit = bytearray()
        auddit.extend([0] * 4)
        auddit.extend(server_seq_num.to_bytes(4, "big"))
        auddit.extend(self.record_type.to_bytes(1, "big"))
        auddit.extend(self.version.to_bytes(2, "big"))
        fill_len = self.length + 0x10
        auddit.extend(fill_len.to_bytes(2, "big"))
        cipher = Cipher(
            algorithms.AES(keys.server_key),
            modes.GCM(nonce), 
            backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(auddit)
        ciphertext = encryptor.update(self.data) + encryptor.finalize()
        self.data = ciphertext + encryptor.tag
        self.length = len(self.data)
        return 0

    def decrypt(self, keys: 'TrafficKeyPair', client_seq_num: int) -> int:
        nonce = keys.client_nonce
        nonce = xor_nonce(nonce, client_seq_num)
        auddit = bytearray()
        auddit.extend([0] * 4)
        auddit.extend(client_seq_num.to_bytes(4, "big"))
        auddit.extend(self.record_type.to_bytes(1, "big"))
        auddit.extend(self.version.to_bytes(2, "big"))
        auddit.extend(self.length.to_bytes(2, "big"))
        cipher = Cipher(
            algorithms.AES(keys.client_key),
            modes.GCM(nonce, self.data[-16:]), 
            backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(auddit)
        try:
            plaintext = decryptor.update(self.data[:-16]) + decryptor.finalize()
        except InvalidTag:
            return -1
        self.data = plaintext
        self.length = len(self.data)
        return 0
    