# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:41:25 2024

@author: Jack Li
"""


class Signature:
    def __init__(self):
        self.type: int = 0
        self.ecdsa_signature: bytes or None = None
    
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
