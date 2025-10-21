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
        self._hasher = self._hash()
        self._clen = 0

    def write(self, content: bytes) -> int:
        self._hasher.update(content)
        self._clen += len(content)
        return self._clen

    def reset(self):
        self._hasher = self._hash()

    def sum(self, extra_content: bytes = b'') -> bytes:
        self.write(extra_content)
        return self._hasher.digest()
