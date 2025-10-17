# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:40:35 2024

@author: Jack Li
"""
from typing import Union


class ServerFinish:
    def __init__(self):
        self.reserved: int = 0
        self.data: Union[bytes, None] = None
        
    @classmethod
    def read_server_finish(cls, data: bytes) -> 'ServerFinish':
        instance = cls()
        data = data[4:]
        reserved = data[0]
        data = data[1:]
        length = (data[0] << 8) | data[1]
        data = data[2:2+length]
        instance.reserved = reserved
        instance.data = data
        return instance

    @classmethod
    def new_server_finish(cls, data: bytes) -> 'ServerFinish':
        instance = cls()
        instance.reserved = 0x14
        instance.data = data
        return instance

    def serialize(self) -> bytes:
        result = bytearray()
        result.extend([0] * 4)
        result.append(self.reserved)
        result.extend(len(self.data).to_bytes(2, "big"))
        result.extend(self.data)
        result[:4] = (len(result) - 4).to_bytes(4, "big")
        return bytes(result)
