# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:40:09 2024

@author: Jack Li
"""

import hashlib
import hmac
import requests
from .hand_shake_hasher import HandShakeHasher
from .session import Session, TrafficKeyPair
from .record import MMTLSRecord
from .client_hello import ClientHello
from .server_hello import ServerHello
from .utility import hkdf_expand, get_random_key, get_logger, get_host_by_name
from .const import TLS_PSK_WITH_AES_128_GCM_SHA256
from typing import Union


class MMTLSClientShort:
    def __init__(self):
        self.status: int = 0
        self.packet_reader: Union[bytes, None] = None
        self.hand_shake_hasher: Union['HandShakeHasher', None] = None
        self.server_seq_num: int = 0
        self.client_seq_num: int = 0
        self.session: Union['Session', None] = None
        self.app_key: Union['TrafficKeyPair', None] = None
        self.hand_shake_hasher = HandShakeHasher(hashlib.sha256)
        self.logger = get_logger()

    def request(self,
                host: str,
                path: str,
                data: bytes) -> bytes:
        self.logger.info("Short link request begin!!!!")
        result = bytearray()
        try:
            ip = get_host_by_name(host)
            assert self.session is not None, "session is None"
            http_packet = self.pack_http(ip, path, data)
            headers = {
                "Host": host,
                "Accept": "*/*",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Content-Length": str(len(http_packet)),
                "Content-Type": "application/octet-stream",
                "Upgrade": "mmtls",
                "User-Agent": "MicroMessenger Client",
                "X-Online-Host": host
            }
            random_arr = get_random_key(2)
            random_name = (random_arr[0] << 8) | (random_arr[1] << 1)
            url = "http://%s/mmtls/%08x" % (host, random_name)
            resp = requests.post(url, data=http_packet, headers=headers)
            assert resp.status_code == 200
            self.packet_reader = resp.content
            rc = self.read_server_hello()
            assert rc >= 0
            traffic_key = self.compute_traffic_key(
                self.session.psk_access,
                self.hkdf_expand("handshake key expansion",
                                 self.hand_shake_hasher)
            )
            self.app_key = traffic_key
            rc = self.read_server_finish()
            assert rc >= 0
            data_record = self.read_data_record()
            assert data_record.length > 0
            rc = self.read_abort()
            assert rc >= 0
            result.extend(data_record.data)
        except AssertionError:
            pass
        finally:
            self.logger.info("Short link request end!!!!")
        return bytes(result)

    def close(self) -> int:
        self.status = 0
        return 0

    def pack_http(self,
                  host: str,
                  path: str,
                  data: bytes
                  ) -> bytes:
        tls_payload = bytearray()
        dat_part = self.gen_data_part(host, path, data)
        hello = ClientHello.new_pskzero_hello(self.session.tk.tickets[0])
        hello_part = hello.serialize()
        self.hand_shake_hasher.write(hello_part)
        early_key = self.early_data_key(self.session.psk_access)
        record_data = MMTLSRecord.create_system_record(hello_part).serialize()
        tls_payload.extend(record_data)
        self.client_seq_num += 1
        extensions_part = bytearray([
            0x00, 0x00, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00,
            0x0b, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x12,
        ])
        extensions_part.extend(hello.timestamp.to_bytes(4, 'big'))
        self.hand_shake_hasher.write(extensions_part)
        extensions_record = MMTLSRecord.create_system_record(extensions_part)
        rc = extensions_record.encrypt(early_key, self.client_seq_num)
        assert rc >= 0
        record_data = extensions_record.serialize()
        tls_payload.extend(record_data)
        self.client_seq_num += 1
        request_record = MMTLSRecord.create_raw_data_record(dat_part)
        rc = request_record.encrypt(early_key, self.client_seq_num)
        assert rc >= 0
        record_data = request_record.serialize()
        tls_payload.extend(record_data)
        self.client_seq_num += 1
        abort_part = bytearray([0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01])
        abort_record = MMTLSRecord.create_abort_record(abort_part)
        rc = abort_record.encrypt(early_key, self.client_seq_num)
        assert rc >= 0
        record_data = abort_record.serialize()
        tls_payload.extend(record_data)
        self.client_seq_num += 1
        result = tls_payload
        self.logger.info(result.hex().upper())
        return result

    @staticmethod
    def gen_data_part(host: str,
                      path: str,
                      data: bytes
                      ) -> bytes:
        result = bytearray()
        result.extend([0] * 4)
        result.extend(len(path.encode()).to_bytes(2, 'big'))
        result.extend(path.encode())
        result.extend(len(host.encode()).to_bytes(2, 'big'))
        result.extend(host.encode())
        result.extend(len(data).to_bytes(4, 'big'))
        result.extend(data)
        length = len(result) - 4
        result[:4] = length.to_bytes(4, 'big')
        return result

    def read_server_hello(self) -> int:
        server_hello_record = MMTLSRecord.read_record(self.packet_reader)
        self.packet_reader = self.packet_reader[5 + server_hello_record.length:]
        self.hand_shake_hasher.write(server_hello_record.data)
        self.server_seq_num += 1
        self.logger.info(server_hello_record.data.hex().upper())
        server_hello = ServerHello.read_server_hello(server_hello_record.data)
        if server_hello.cipher_suite == TLS_PSK_WITH_AES_128_GCM_SHA256:
            return 0
        elif server_hello.cipher_suite == 0x7302:
            self.logger.info("session expired")
            return -2
        return -1

    def read_server_finish(self) -> int:
        server_finish_record = MMTLSRecord.read_record(self.packet_reader)
        self.packet_reader = self.packet_reader[5 + server_finish_record.length:]
        rc = server_finish_record.decrypt(self.app_key, self.server_seq_num)
        assert rc >= 0
        self.server_seq_num += 1
        self.logger.info(server_finish_record.data.hex().upper())
        return 0

    def read_data_record(self) -> 'MMTLSRecord':
        record = MMTLSRecord.read_record(self.packet_reader)
        self.packet_reader = self.packet_reader[5 + record.length:]
        rc = record.decrypt(self.app_key, self.server_seq_num)
        assert rc >= 0
        self.server_seq_num += 1
        self.logger.info(record.data.hex().upper())
        return record

    def read_abort(self) -> int:
        record = MMTLSRecord.read_record(self.packet_reader)
        self.packet_reader = self.packet_reader[5 + record.length:]
        rc = record.decrypt(self.app_key, self.server_seq_num)
        assert rc >= 0
        self.server_seq_num += 1
        self.logger.info(record.data.hex().upper())
        return 0

    def early_data_key(self,
                       psk_access: bytes) -> 'TrafficKeyPair':
        traffic_key_data = hkdf_expand(hashlib.sha256,
                                       psk_access,
                                       self.hkdf_expand("early data key expansion", self.hand_shake_hasher),
                                       28)
        pair = TrafficKeyPair()
        pair.client_key = traffic_key_data[:16]
        pair.client_nonce = traffic_key_data[16:]
        return pair

    @staticmethod
    def compute_traffic_key(share_key: bytes,
                            info: bytes) -> 'TrafficKeyPair':
        traffic_key_data = hkdf_expand(hashlib.sha256,
                                       share_key,
                                       info,
                                       28)
        pair = TrafficKeyPair()
        pair.server_key = traffic_key_data[:16]
        pair.server_nonce = traffic_key_data[16:]
        return pair

    @staticmethod
    def hkdf_expand(prefix: str,
                    hasher: 'HandShakeHasher' = None) -> bytes:
        result = bytearray(prefix.encode())
        if hasher is not None:
            hash_sum = hasher.sum()
            result.extend(hash_sum)
        return bytes(result)

    @staticmethod
    def hmac(k: bytes, d: bytes) -> bytes:
        hmac_sha256 = hmac.new(k, d, digestmod=hashlib.sha256)
        result = hmac_sha256.digest()
        return result
