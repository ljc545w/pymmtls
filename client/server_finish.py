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
