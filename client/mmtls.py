# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:40:00 2024

@author: Jack Li
"""

import socket
import hashlib
import ecdsa
import hmac
import ecdsa.ellipticcurve
import ecdsa.util
from ecdsa.ellipticcurve import PointJacobi
from .hand_shake_hasher import HandShakeHasher
from .session import Session, TrafficKeyPair
from .client_hello import ClientHello
from .client_finish import ClientFinish
from .server_hello import ServerHello
from .server_finish import ServerFinish
from .session_ticket import NewSessionTicket
from .record import MMTLSRecord
from .signature import Signature
from .const import Curve, ServerEcdh, TCP_NoopRequest, TCP_NoopResponse
from .utility import get_host_by_name, hkdf_expand, get_logger


class MMTLSClient:
    def __init__(self):
        self.conn: 'socket.socket' or None = None
        self.status: int = 0
        self.public_ecdh: 'ecdsa.keys.SigningKey' or None = None
        self.verify_ecdh: 'ecdsa.keys.SigningKey' or None = None
        self.server_ecdh: 'ecdsa.keys.SigningKey' or None = None
        self.hand_shake_hasher: 'HandShakeHasher' or None = None
        self.server_seq_num: int = 0
        self.client_seq_num: int = 0
        self.session: 'Session' or None = None
        self.hand_shake_hasher = HandShakeHasher(hashlib.sha256)
        self.logger = get_logger()

    def hand_shake(self, host: str, port: int = 80) -> int:
        self.logger.info("Long link handshake begin!!!!")
        rc = 0
        try:
            ip = get_host_by_name(host)
            traffic_key = TrafficKeyPair()
            app_key = TrafficKeyPair()
            assert (self.hand_shake_complete is not True)
            self.conn = socket.socket(socket.AF_INET, 
                                      socket.SOCK_STREAM,
                                      socket.IPPROTO_TCP)
            self.conn.connect((ip, port))
            self.reset()
            rc = self.gen_key_pairs()
            assert rc >= 0
            public_ecdh_der = self.public_ecdh.get_verifying_key().to_string("uncompressed")
            verify_ecdh_der = self.verify_ecdh.get_verifying_key().to_string("uncompressed")
            if self.session is not None and len(self.session.tk.tickets) > 1:
                client_hello = ClientHello.new_pskone_hello(
                    public_ecdh_der, 
                    verify_ecdh_der, 
                    self.session.tk.tickets[1])
            else:
                client_hello = ClientHello.new_ecdh_hello(
                    public_ecdh_der, 
                    verify_ecdh_der)
            rc = self.send_client_hello(client_hello)
            assert rc >= 0
            server_hello = self.read_server_hello()
            server_public_key = ecdsa.VerifyingKey.from_string(server_hello.public_key, Curve)
            public_ecdh_private_key = self.public_ecdh.privkey.secret_multiplier
            com_key = self.compute_ephemeral_secret(
                server_public_key.pubkey.point, 
                public_ecdh_private_key)
            rc = self.compute_traffic_key(
                com_key, 
                self.hkdf_expand("handshake key expansion", self.hand_shake_hasher), 
                traffic_key)
            assert rc >= 0
            rc = self.read_signature(traffic_key)
            assert rc >= 0
            rc = self.read_new_session_ticket(com_key, traffic_key)
            assert rc >= 0
            rc = self.read_server_finish(com_key, traffic_key)
            assert rc >= 0
            rc = self.send_client_finish(com_key, traffic_key)
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
            self.logger.info("Long link handshake end!!!!error_code: %d" % rc)
        return rc
    
    def noop(self) -> int:
        self.logger.info("Long link noop begin!!!!")
        rc = self.send_noop()
        if rc >= 0:
            rc = self.read_noop()
        self.logger.info("Long link noop end!!!!error_code: %d" % rc)
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
    
    def send_client_hello(self, hello: 'ClientHello') -> int:
        data = hello.serialize()
        self.hand_shake_hasher.write(data)
        packet = MMTLSRecord.create_handshake_record(data).serialize()
        s_len = self.conn.send(packet)
        self.client_seq_num += 1
        if s_len == -1:
            return -1
        self.logger.info(packet.hex().upper())
        return 0
    
    def read_server_hello(self) -> 'ServerHello':
        record = MMTLSRecord()
        rc = self.read_record(record)
        assert rc >= 0
        self.hand_shake_hasher.write(record.data)
        self.server_seq_num += 1
        hello = ServerHello.read_server_hello(record.data)
        self.logger.info(record.data.hex().upper())
        return hello
    
    def read_signature(self, traffic_key: 'TrafficKeyPair') -> int:
        record = MMTLSRecord()
        rc = self.read_record(record)
        assert rc >= 0
        rc = record.decrypt(traffic_key, self.server_seq_num)
        assert rc >= 0
        sign = Signature.read_signature(record.data)
        if not self.verify_ecdsa(sign.ecdsa_signature):
            return -1
        self.hand_shake_hasher.write(record.data)
        self.server_seq_num += 1
        self.logger.info(record.data.hex().upper())
        return 0
    
    def read_new_session_ticket(self, 
                                com_key: bytes, 
                                traffic_key: 'TrafficKeyPair') -> int:
        record = MMTLSRecord()
        rc = self.read_record(record)
        assert rc >= 0
        rc = record.decrypt(traffic_key, self.server_seq_num)
        assert rc >= 0
        new_session_ticket = NewSessionTicket.read_new_session_ticket(record.data)
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
        self.hand_shake_hasher.write(record.data)
        self.server_seq_num += 1
        self.logger.info(record.data.hex().upper())
        return 0
    
    def read_server_finish(self, 
                           com_key: bytes, 
                           traffic_key: 'TrafficKeyPair') -> int:
        record = MMTLSRecord()
        rc = self.read_record(record)
        assert rc >= 0
        rc = record.decrypt(traffic_key, self.server_seq_num)
        assert rc >= 0
        server_finish = ServerFinish.read_server_finish(record.data)
        server_finish_key = hkdf_expand(
            hashlib.sha256, 
            com_key, 
            self.hkdf_expand("server finished"), 
            32)
        digest = self.hand_shake_hasher.sum()
        security_param = self.hmac(server_finish_key, digest)
        if server_finish.data != security_param:
            return -1
        self.server_seq_num += 1
        self.logger.info(record.data.hex().upper())
        return 0
    
    def send_client_finish(self, 
                           com_key: bytes, 
                           traffic_key: 'TrafficKeyPair') -> int:
        client_finish_key = hkdf_expand(
            hashlib.sha256, 
            com_key, 
            self.hkdf_expand("client finished"), 
            32)
        digest = self.hand_shake_hasher.sum()
        security_param = self.hmac(client_finish_key, digest)
        client_finish = ClientFinish.new_client_finish(security_param)
        client_finish_record = MMTLSRecord.create_handshake_record(
            client_finish.serialize()
            )
        rc = client_finish_record.encrypt(traffic_key, self.client_seq_num)
        assert rc >= 0
        packet = client_finish_record.serialize()
        s_len = self.conn.send(packet)
        self.client_seq_num += 1
        if s_len == -1:
            return -1
        self.logger.info(packet.hex().upper())
        return 0
    
    def send_noop(self) -> int:
        noop_record = MMTLSRecord.create_data_record(
            TCP_NoopRequest, 
            0xffffffff, 
            b"")
        rc = noop_record.encrypt(self.session.app_key, self.client_seq_num)
        assert rc >= 0
        packet = noop_record.serialize()
        s_len = self.conn.send(packet)
        self.client_seq_num += 1
        if s_len == -1:
            return -1
        self.logger.info(packet.hex().upper())
        return 0
    
    def read_noop(self) -> int:
        record = MMTLSRecord()
        rc = self.read_record(record)
        assert rc >= 0
        rc = record.decrypt(self.session.app_key, self.server_seq_num)
        assert rc >= 0
        data = record.data
        pack_len = int.from_bytes(data[:4], 'big')
        data = data[4:]
        if pack_len != 0x10:
            return -1
        # skip flag
        data = data[4:]
        data_type = int.from_bytes(data[:4], 'big')
        # data = data[4:]
        if data_type != TCP_NoopResponse:
            return -1
        self.server_seq_num += 1
        self.logger.info(record.data.hex().upper())
        return 0
    
    def read_record(self, record: 'MMTLSRecord') -> int:
        if self.conn is None:
            return -1
        header = self.conn.recv(5)
        if len(header) == 0:
            return -1
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
    
    def verify_ecdsa(self, data: bytes) -> bool:
        digest = self.hand_shake_hasher.sum()
        try:
            verify = ServerEcdh.verify(data, 
                                       digest, 
                                       hashfunc=hashlib.sha256,
                                       sigdecode=ecdsa.util.sigdecode_der)
        except ecdsa.keys.BadSignatureError:
            verify = False
        return verify
    
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
        self.verify_ecdh = ecdsa.SigningKey.generate(Curve)
        return 0
    