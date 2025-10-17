# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:41:08 2024

@author: Jack Li
"""
import os
from typing import Union
from .session_ticket import NewSessionTicket


class TrafficKeyPair:
    def __init__(self):
        self.client_key: Union[bytes, None] = None
        self.server_key: Union[bytes, None] = None
        self.client_nonce: Union[bytes, None] = None
        self.server_nonce: Union[bytes, None] = None


class Session:
    def __init__(self,
                 timestamp: int,
                 resume_key: bytes,
                 tk: 'NewSessionTicket', 
                 psk_access: bytes, 
                 psk_refresh: bytes):
        self.timestamp: int = timestamp
        self.resume_key: Union[bytes, None] = resume_key
        self.tk = tk
        self.psk_access = psk_access
        self.psk_refresh = psk_refresh
        
    def save(self, path: str) -> bool:
        result = self.serialize()
        with open(path, "wb") as f:
            f.write(result)
            f.close()
        return True
    
    def serialize(self) -> bytes:
        result = bytearray()
        result.extend(self.timestamp.to_bytes(4, 'big'))
        result.extend(len(self.resume_key).to_bytes(2, 'big'))
        result.extend(self.resume_key)
        result.extend(len(self.psk_access).to_bytes(2, 'big'))
        result.extend(self.psk_access)
        result.extend(len(self.psk_refresh).to_bytes(2, 'big'))
        result.extend(self.psk_refresh)
        result.extend(self.tk.serialize())
        return bytes(result)
    
    @classmethod
    def load_session(cls, path: str) -> Union['Session', None]:
        if not os.path.exists(path):
            return None
        try:
            content = open(path, "rb").read()
            return cls.parse_from_string(content)
        except IndexError:
            return None
    
    @classmethod
    def parse_from_string(cls, content: bytes) -> 'Session':
        timestamp = int.from_bytes(content[:4], 'big')
        content = content[4:]
        length = int.from_bytes(content[:2], 'big')
        content = content[2:]
        resume_key = content[:length]
        content = content[length:]
        length = int.from_bytes(content[:2], 'big')
        content = content[2:]
        psk_access = content[:length]
        content = content[length:]
        length = int.from_bytes(content[:2], 'big')
        content = content[2:]
        psk_refresh = content[:length]
        content = content[length:]
        tk = NewSessionTicket.read_new_session_ticket(content)
        instance = cls(timestamp, resume_key, tk, psk_access, psk_refresh)
        return instance
