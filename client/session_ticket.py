# -*- coding: utf-8 -*-
"""
Created on Fri Jun 21 16:41:16 2024

@author: Jack Li
"""
from typing import List


class SessionTicket:
    def __init__(self):
        self.ticket_type: int = 0
        self.ticket_life_time: int = 0
        self.ticket_age_add: bytes or None = None
        self.reserved: int = 0
        self.nonce: bytes or None = None
        self.ticket: bytes or None = None

    def serialize(self) -> 'bytes':
        result = bytearray()
        result.extend(self.ticket_type.to_bytes(1, 'big'))
        result.extend(self.ticket_life_time.to_bytes(4, 'big'))
        result.extend(len(self.ticket_age_add).to_bytes(2, 'big'))
        result.extend(self.ticket_age_add)
        result.extend(self.reserved.to_bytes(4, 'big'))
        result.extend(len(self.nonce).to_bytes(2, 'big'))
        result.extend(self.nonce)
        result.extend(len(self.ticket).to_bytes(2, 'big'))
        result.extend(self.ticket)
        return bytes(result)

    @classmethod
    def read_session_ticket(cls, data: bytes) -> 'SessionTicket':
        instance = cls()
        instance.ticket_type = data[0]
        data = data[1:]
        instance.ticket_life_time = int.from_bytes(data[:4], 'big')
        data = data[4:]

        length = int.from_bytes(data[:2], 'big')
        data = data[2:]
        instance.ticket_age_add = data[:length]
        data = data[length:]

        instance.reserved = int.from_bytes(data[:4], 'big')
        data = data[4:]

        length = int.from_bytes(data[:2], 'big')
        data = data[2:]
        instance.nonce = data[:length]
        data = data[length:]

        length = int.from_bytes(data[:2], 'big')
        data = data[2:]
        instance.ticket = data[:length]
        # data = data[length:]
        return instance


class NewSessionTicket:
    def __init__(self):
        self.reserved: int = 0
        self.count: int = 0
        self.tickets: List[SessionTicket] = []

    def serialize(self) -> 'bytes':
        result = bytearray()
        result.extend([0] * 4)
        result.append(0x4)
        result.append(len(self.tickets) & 0xff)
        for ticket in self.tickets:
            ticket_data = ticket.serialize()
            result.extend(len(ticket_data).to_bytes(4, 'big'))
            result.extend(ticket_data)
        d_len = len(result) - 4
        result[0:4] = d_len.to_bytes(4, 'big')
        return bytes(result)

    def export(self) -> 'bytes':
        result = bytearray()
        if len(self.tickets) == 0:
            return bytes(result)
        ticket_data = self.tickets[0].serialize()
        result.extend(len(ticket_data).to_bytes(4, 'big'))
        result.extend(ticket_data)
        return bytes(result)

    @classmethod
    def read_new_session_ticket(cls, data: bytes) -> 'NewSessionTicket':
        instance = cls()
        length = int.from_bytes(data[:4], 'big')
        assert length != 0
        data = data[4:]
        instance.reserved = data[0]
        data = data[1:]
        instance.count = data[0]
        data = data[1:]
        for i in range(instance.count):
            length = int.from_bytes(data[:4], 'big')
            data = data[4:]
            ticket_data = data[:length]
            data = data[length:]
            ticket = SessionTicket.read_session_ticket(ticket_data)
            instance.tickets.append(ticket)
        return instance
