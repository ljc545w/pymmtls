# -*- coding: utf-8 -*-
"""
Created on Thu Jul 13 14:35:40 2024

@author: Jack Li
"""
import os
import sys

local_path = os.path.split(os.path.abspath(__file__))[0]
sys.path.append(os.path.join(local_path, ".."))

from client import MMTLSClient, Session
from server import const as server_const


def test_mmtls_client():
    host = "127.0.0.1"
    port = 7892
    client = MMTLSClient(server_const.ServerVerifyEcdh)
    session = Session.load_session(os.path.join(local_path, "client.session"))
    client.session = session
    err = client.hand_shake(host, port)
    if err >= 0:
        client.session.save(os.path.join(local_path, "client.session"))
        while True:
            cmd = input(">>> ")
            if cmd == "quit":
                break
            client.noop()
    client.close()


if __name__ == "__main__":
    test_mmtls_client()
