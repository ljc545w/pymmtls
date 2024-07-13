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
ServerEcdhSrc = ("307702010104204278b98b02fb5c54cc61cfa661a4932ab382134ffbd9bdd021a6fdab0dedb155a00a06082a8648ce3d03010"
                 "7a144034200049e1cc80d6f65ba5d83d132fea83fb3d3e3c9168ef6d4d6958dc424fd52bdafd75400ce69a6170fcdf2f2d479"
                 "fab9a320d91b7d8b2e741ffd86972e785e683eae")
Curve = ecdsa.NIST256p
ServerEcdh = ecdsa.SigningKey.from_der(bytes.fromhex(ServerEcdhSrc))
ServerVerifyEcdh = ServerEcdh.get_verifying_key()

TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0x0300C02B
