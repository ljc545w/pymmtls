# -*- coding: utf-8 -*-
"""
Created on Thu Jul 13 14:35:40 2024

@author: Jack Li
"""

import os
import sys

local_path = os.path.split(os.path.abspath(__file__))[0]
sys.path.append(os.path.join(local_path, ".."))

from server import MMTLSServer

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 7892
    print("mmtls server is running on: %s:%d" % (host, port))
    MMTLSServer().run_forever(host, port)
