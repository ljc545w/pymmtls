# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:41:25 2024

@author: Jack Li
"""
from typing import Union


class Signature:
    def __init__(self):
        self.type: int = 0
        self.ecdsa_signature: Union[bytes, None] = None
    
    @classmethod
    def read_signature(cls, data: bytes) -> 'Signature':
        instance = cls()
        # skip package length
        data = data[4:]
        # static 0x0f
        instance.type = data[0]
        data = data[1:]
        length = int.from_bytes(data[:2], 'big')
        data = data[2:]
        instance.ecdsa_signature = data[:length]
        # data = data[length:]
        return instance

    @classmethod
    def new_signature(cls, data: bytes) -> 'Signature':
        instance = cls()
        instance.type = 0x0f
        instance.ecdsa_signature = data
        return instance

    def serialize(self) -> bytes:
        result = bytearray()
        result.extend([0] * 4)
        result.append(self.type & 0xff)
        result.extend(len(self.ecdsa_signature).to_bytes(2, "big"))
        result.extend(self.ecdsa_signature)
        length = len(result) - 4
        result[:4] = length.to_bytes(4, "big")
        return bytes(result)
