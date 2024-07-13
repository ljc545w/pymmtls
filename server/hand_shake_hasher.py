# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:39:50 2024

@author: Jack Li
"""

import hashlib


class HandShakeHasher:
    # noinspection PyProtectedMember
    def __init__(self, _hash: 'hashlib._hashlib.Hash'):
        self._hash = _hash
        self._content = bytearray()

    def write(self, content: bytes) -> int:
        self._content.extend(content)
        return len(content)

    def reset(self):
        self._content.clear()

    def sum(self, extra_content: bytes = b'') -> bytes:
        self.write(extra_content)
        hasher = self._hash()
        hasher.update(bytes(self._content))
        return hasher.digest()
