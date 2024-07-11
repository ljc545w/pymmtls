# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:39:17 2024

@author: Jack Li
"""

import ecdsa

POINT_CONVERSION_UNCOMPRESSED = "04"

ProtocolVersion = 0xF104
TLS_PSK_WITH_AES_128_GCM_SHA256 = 0xA8
MagicAbort = 0x15
MagicHandshake = 0x16
MagicRecord = 0x17
MagicSystem = 0x19

TCP_NoopRequest = 0x6
TCP_NoopResponse = 0x3B9ACA06

TCP_Request = 0x00
TCP_Response = 0x3B9ACA00
ServerEcdhCurveId = 415
ServerEcdhX = "1da177b6a5ed34dabb3f2b047697ca8bbeb78c68389ced43317a298d77316d54"
ServerEcdhY = "4175c032bc573d5ce4b3ac0b7f2b9a8d48ca4b990ce2fa3ce75cc9d12720fa35"
Curve = ecdsa.NIST256p
ServerEcdh = ecdsa.VerifyingKey.from_string(
    bytes.fromhex(POINT_CONVERSION_UNCOMPRESSED + ServerEcdhX + ServerEcdhY), 
    Curve)

TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0x0300C02B
