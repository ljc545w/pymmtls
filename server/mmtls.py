# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:40:00 2024

@author: Jack Li
"""

import socket
import time

import select
import hashlib

import ecdsa
import hmac
import ecdsa.ellipticcurve
import ecdsa.util
import threading
from ecdsa.ellipticcurve import PointJacobi
from typing import Dict
from .hand_shake_hasher import HandShakeHasher
from .session import Session, TrafficKeyPair
from .client_hello import ClientHello
from .client_finish import ClientFinish
from .server_hello import ServerHello
from .server_finish import ServerFinish
from .session_ticket import NewSessionTicket
from .record import MMTLSRecord, DataRecord
from .signature import Signature
from .const import Curve, ServerEcdh, TCP_NoopRequest, TCP_NoopResponse
from .utility import hkdf_expand, get_logger, singleton


@singleton
class MMTLSServer:
    def __init__(self):
        self.server: 'socket.socket' or None = None
        self.clients: Dict[int, MMTLSConnection] = {}

    def run_forever(self, host, port):
        self.server = socket.socket(socket.AF_INET,
                                    socket.SOCK_STREAM,
                                    socket.IPPROTO_TCP)
        self.server.setsockopt(socket.SOL_SOCKET,
                               socket.SO_REUSEADDR,
                               1)
        self.server.bind((host, port))
        self.server.listen(5)
        num = 0
        while True:
            num += 1
            conn, address = self.server.accept()
            client = MMTLSConnection(conn, address, num)
            client_handler = threading.Thread(target=client.keep_alive)
            client_handler.daemon = True
            client_handler.start()
            self.clients[num] = client


class MMTLSConnection:
    def __init__(self, conn: 'socket.socket', address: tuple, client_id: int):
        self.conn: 'socket.socket' = conn
        self.address: tuple = address
        self.client_id = client_id
        self.status: int = 0
        self.public_ecdh: 'ecdsa.keys.SigningKey' or None = None
        self.verify_ecdh: 'ecdsa.keys.SigningKey' = ServerEcdh
        self.server_seq_num: int = 0
        self.client_seq_num: int = 0
        self.time_out: int = 35
        self.session: 'Session' or None = None
        self.hand_shake_hasher = HandShakeHasher(hashlib.sha256)
        self.logger = get_logger()

    def keep_alive(self):
        # FIONREAD = (0x40000000 | ((4 & 0x7f) << 16) | (ord('f') << 8) | 127)
        if self.hand_shake() != 0:
            self.close()
            MMTLSServer().clients.pop(self.client_id)
            return
        while True:
            try:
                data_record = self.read_data_record()
                if data_record is None:
                    time.sleep(0.001)
                    continue
                if data_record.data_type == TCP_NoopRequest:
                    rc = self.send_data_record(TCP_NoopResponse, data_record.seq, b"")
                    assert rc >= 0
                else:
                    print("unknown data type: %d" % data_record.data_type)
                    break
            except socket.error as e:
                self.logger.error(str(e))
                break
            except AssertionError as e:
                self.logger.error(str(e))
                break
        self.logger.info("Client %d is shutdowning..." % self.client_id)
        MMTLSServer().clients.pop(self.client_id)
        self.close()

    def hand_shake(self) -> int:
        self.logger.info("Long link %d handshake begin, Address: %s:%d" %
                         (self.client_id, self.address[0], self.address[1])
                         )
        rc = 0
        try:
            traffic_key = TrafficKeyPair()
            app_key = TrafficKeyPair()
            assert (self.hand_shake_complete is not True)
            self.reset()
            rc = self.gen_key_pairs()
            assert rc >= 0
            public_ecdh_der = self.public_ecdh.get_verifying_key().to_string("uncompressed")
            client_hello = self.read_client_hello()
            server_hello = ServerHello.new_ecdh_hello(public_ecdh_der)
            rc = self.send_server_hello(server_hello)
            assert rc >= 0
            client_public_key = ecdsa.VerifyingKey.from_string(client_hello.get_client_public_key(), Curve)
            public_ecdh_private_key = self.public_ecdh.privkey.secret_multiplier
            com_key = self.compute_ephemeral_secret(
                client_public_key.pubkey.point,
                public_ecdh_private_key)
            rc = self.compute_traffic_key(
                com_key,
                self.hkdf_expand("handshake key expansion", self.hand_shake_hasher),
                traffic_key)
            assert rc >= 0
            rc = self.send_signature(traffic_key)
            assert rc >= 0
            rc = self.send_new_session_ticket(com_key, traffic_key)
            assert rc >= 0
            rc = self.send_server_finish(com_key, traffic_key)
            assert rc >= 0
            rc = self.read_client_finish(com_key, traffic_key)
            assert rc >= 0
            expanded_secret = hkdf_expand(
                hashlib.sha256,
                com_key,
                self.hkdf_expand("expanded secret", self.hand_shake_hasher),
                32)
            rc = self.compute_traffic_key(
                expanded_secret,
                self.hkdf_expand("application data key expansion", self.hand_shake_hasher),
                app_key)
            assert rc >= 0
            self.session.app_key = app_key
            self.status = 1
        except AssertionError:
            rc = -1
        finally:
            self.logger.info("Long link %d handshake end!!!!error_code: %d" % (self.client_id, rc))
        return rc

    def close(self) -> int:
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        self.status = 0
        return 0

    def reset(self) -> int:
        self.client_seq_num = 0
        self.server_seq_num = 0
        self.hand_shake_hasher.reset()
        return 0

    @property
    def hand_shake_complete(self) -> bool:
        return self.status == 1

    def read_client_hello(self) -> 'ClientHello':
        record = MMTLSRecord()
        rc = self.read_record(record)
        assert rc >= 0
        self.hand_shake_hasher.write(record.data)
        self.client_seq_num += 1
        hello = ClientHello.read_client_hello(record.data)
        self.logger.info(record.data.hex().upper())
        return hello

    def send_server_hello(self, hello: 'ServerHello') -> int:
        data = hello.serialize()
        self.hand_shake_hasher.write(data)
        packet = MMTLSRecord.create_handshake_record(data).serialize()
        s_len = self.conn.send(packet)
        self.server_seq_num += 1
        if s_len == -1:
            return -1
        self.logger.info(packet.hex().upper())
        return 0

    def send_signature(self, traffic_key: 'TrafficKeyPair') -> int:
        digest = self.hand_shake_hasher.sum()
        sign_data = self.verify_ecdh.sign(digest,
                                          hashfunc=hashlib.sha256,
                                          sigencode=ecdsa.util.sigencode_der)
        signature = Signature.new_signature(sign_data)
        record = MMTLSRecord.create_handshake_record(signature.serialize())
        self.hand_shake_hasher.write(record.data)
        rc = record.encrypt(traffic_key, self.server_seq_num)
        assert rc >= 0
        packet_data = record.serialize()
        s_len = self.conn.send(packet_data)
        assert s_len == len(packet_data)
        self.server_seq_num += 1
        self.logger.info(record.data.hex().upper())
        return 0

    def send_new_session_ticket(self,
                                com_key: bytes,
                                traffic_key: 'TrafficKeyPair') -> int:
        new_session_ticket = NewSessionTicket.create_new_session_ticket()
        record = MMTLSRecord.create_system_record(new_session_ticket.serialize())
        self.hand_shake_hasher.write(record.data)
        rc = record.encrypt(traffic_key, self.server_seq_num)
        assert rc >= 0
        packet_data = record.serialize()
        s_len = self.conn.send(packet_data)
        assert s_len == len(packet_data)
        psk_access = hkdf_expand(
            hashlib.sha256,
            com_key,
            self.hkdf_expand("PSK_ACCESS", self.hand_shake_hasher),
            32)
        psk_refresh = hkdf_expand(
            hashlib.sha256,
            com_key,
            self.hkdf_expand("PSK_REFRESH", self.hand_shake_hasher),
            32)
        self.session = Session(new_session_ticket, psk_access, psk_refresh)
        self.server_seq_num += 1
        self.logger.info(record.data.hex().upper())
        return 0

    def send_server_finish(self,
                           com_key: bytes,
                           traffic_key: 'TrafficKeyPair') -> int:
        server_finish_key = hkdf_expand(
            hashlib.sha256,
            com_key,
            self.hkdf_expand("server finished"),
            32)
        digest = self.hand_shake_hasher.sum()
        security_param = self.hmac(server_finish_key, digest)
        server_finish = ServerFinish.new_server_finish(security_param)
        record = MMTLSRecord.create_handshake_record(server_finish.serialize())
        rc = record.encrypt(traffic_key, self.server_seq_num)
        assert rc >= 0
        packet_data = record.serialize()
        s_len = self.conn.send(packet_data)
        assert s_len == len(packet_data)
        self.server_seq_num += 1
        self.logger.info(record.data.hex().upper())
        return 0

    def read_client_finish(self,
                           com_key: bytes,
                           traffic_key: 'TrafficKeyPair') -> int:
        record = MMTLSRecord()
        rc = self.read_record(record)
        assert rc >= 0
        rc = record.decrypt(traffic_key, self.client_seq_num)
        assert rc >= 0
        client_finish = ClientFinish.read_client_finish(record.data)
        client_finish_key = hkdf_expand(
            hashlib.sha256,
            com_key,
            self.hkdf_expand("client finished"),
            32)
        digest = self.hand_shake_hasher.sum()
        security_param = self.hmac(client_finish_key, digest)
        if client_finish.data != security_param:
            return -1
        self.client_seq_num += 1
        self.logger.info(record.data.hex().upper())
        return 0

    @property
    def readable(self) -> bool:
        readable, _, _ = select.select([self.conn], [], [], self.time_out)
        return self.conn in readable

    def read_data_record(self) -> 'DataRecord' or None:
        record = MMTLSRecord()
        rc = self.read_record(record)
        if rc < 0:
            return None
        rc = record.decrypt(self.session.app_key, self.client_seq_num)
        self.client_seq_num += 1
        assert rc >= 0
        data_record = DataRecord.read_data_record(record.data)
        self.logger.info(record.data.hex())
        return data_record

    def send_data_record(self, data_type: int, seq: int, data: bytes) -> int:
        record = MMTLSRecord.create_data_record(data_type,
                                                seq,
                                                data)
        self.logger.info(record.data.hex())
        rc = record.encrypt(self.session.app_key, self.server_seq_num)
        assert rc >= 0
        self.server_seq_num += 1
        packet = record.serialize()
        s_len = self.conn.send(packet)
        assert s_len == len(packet)
        return 0

    def read_record(self, record: 'MMTLSRecord') -> int:
        if self.conn is None:
            return -1
        readable = self.readable
        if not readable:
            raise socket.error("client has disconnected")
        header = self.conn.recv(5)
        if len(header) == 0:
            raise socket.error("client has disconnected")
        pack_len = (header[3] << 8) | header[4]
        payload = b""
        while len(payload) < pack_len:
            remain_size = pack_len - len(payload)
            block_size = 1024 if remain_size > 1024 else remain_size
            block = self.conn.recv(block_size)
            if len(block) == 0:
                return -1
            payload += block
        data = header + payload
        _record = MMTLSRecord.read_record(data)
        record.record_type = _record.record_type
        record.version = _record.version
        record.length = _record.length
        record.data = _record.data
        return 0

    @staticmethod
    def compute_ephemeral_secret(server_public_key: 'PointJacobi',
                                 public_ecdh_private_key: int) -> bytes:
        point = server_public_key * public_ecdh_private_key
        x = point.x()
        data = x.to_bytes(32, 'big')
        hasher = hashlib.sha256()
        hasher.update(data)
        result = hasher.digest()
        return result

    @staticmethod
    def compute_traffic_key(share_key: bytes,
                            info: bytes,
                            traffic_key: 'TrafficKeyPair') -> int:
        key = hkdf_expand(hashlib.sha256, share_key, info, 56)
        traffic_key.client_key = key[:16]
        traffic_key.server_key = key[16:32]
        traffic_key.client_nonce = key[32:44]
        traffic_key.server_nonce = key[44:]
        return 0

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

    def gen_key_pairs(self) -> int:
        self.public_ecdh = ecdsa.SigningKey.generate(Curve)
        return 0
