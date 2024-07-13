# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:38:19 2024

@author: Jack Li
"""


class ClientFinish:
    def __init__(self):
        self.reserved: int = 0
        self.data: bytes or None = None

    @classmethod
    def new_client_finish(cls, data: bytes) -> 'ClientFinish':
        instance = cls()
        instance.reserved = 0x14
        instance.data = data
        return instance
    
    @classmethod
    def read_client_finish(cls, data: bytes) -> 'ClientFinish':
        instance = cls()
        # length = int.from_bytes(data[:4], "big")
        data = data[4:]
        reserved = data[0]
        data = data[1:]
        # length = int.from_bytes(data[:2], "big")
        data = data[2:]
        instance.reserved = reserved
        instance.data = data
        return instance
    
    def serialize(self) -> bytes:
        result = bytearray()
        d_len = len(self.data) + 3
        result.extend(d_len.to_bytes(4, "big"))
        result.append(self.reserved)
        d_len = len(self.data)
        result.extend(d_len.to_bytes(2, "big"))
        result.extend(self.data)
        return bytes(result)
