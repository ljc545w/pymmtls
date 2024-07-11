# -*- coding: utf-8 -*-
"""
Created on Thu Jul 11 17:35:40 2024

@author: Jack Li
"""

from client import MMTLSClient, MMTLSClientShort, Session
import zlib


def test_mmtls_long():
    client = MMTLSClient()
    session = Session.load_session("session")
    client.session = session
    err = client.hand_shake("szlong.weixin.qq.com")
    client.session.save("session")
    if err >= 0:
        client.noop()
    client.close()


def test_mmtls_short():
    client = MMTLSClientShort()
    session = Session.load_session("session")
    assert session is not None
    client.session = session
    result = client.request("dns.weixin.qq.com.cn", "/cgi-bin/micromsg-bin/newgetdns", b"")
    header, data = tuple(result.split(b"\r\n\r\n"))
    try:
        data = zlib.decompress(data, -zlib.MAX_WBITS)
    except zlib.error:
        data = zlib.decompress(data)
    print(header.decode())
    print("uncompress data len: %d" % len(data))
    client.close()


if __name__ == "__main__":
    test_mmtls_long()
    test_mmtls_short()
