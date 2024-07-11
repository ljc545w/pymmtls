# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:41:36 2024

@author: Jack Li
"""

import random
import socket
import hkdf
import hashlib
import logging

LOGGER_NAME = "MMTLS"
LOGGER = None
LOG_LEVEL = logging.DEBUG


def xor_nonce(nonce: bytes, seq_num: int) -> bytes:
    _nonce = bytearray(nonce)
    seq_data = seq_num.to_bytes(4, 'little')
    for i in range(4):
        pos = len(nonce) - i - 1
        _nonce[pos] ^= seq_data[i]
    return bytes(_nonce)


def get_random_key(length: int) -> bytes:
    key = bytearray()
    for i in range(length):
        key.append(random.randint(0, 255) & 0xff)
    return bytes(key)


def get_host_by_name(host_name: str) -> str:
    ip = socket.gethostbyname(host_name)
    return ip


# noinspection PyProtectedMember
def hkdf_expand(hasher: "hashlib._hashlib.Hash",
                pseudo_random_key: bytes,
                info: bytes,
                length: int) -> bytes:
    return hkdf.hkdf_expand(pseudo_random_key, info, length, hasher)


def get_logger():
    global LOGGER
    if LOGGER is None:
        LOGGER = logging.getLogger(LOGGER_NAME)
        LOGGER.setLevel(LOG_LEVEL)
        ch = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s|%(levelname)s|%(thread)d|%(filename)s[line:%(lineno)d] - %(funcName)s : %(message)s')
        ch.setFormatter(formatter)
        LOGGER.addHandler(ch)
    return LOGGER
