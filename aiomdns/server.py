# -*- coding:utf-8 -*-

__author__ = 'Alexander Rüedlinger'

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('aiomdns')

import socket
import asyncio
import time
from .protocol import create_socket_ipv4
from .protocol import create_socket_ipv6
from .protocol import Message

class ServerProtocol(asyncio.DatagramProtocol):

    def __init__(self, handler):
        super().__init__()
        self._handler = handler
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self._handler(data, addr)

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        pass


class Server(object):

    def __init__(self, loop):
        self._loop = loop
        self._hosts = [];

        # create sockets 
        ipv4_socket = create_socket_ipv4()
        ipv6_socket = create_socket_ipv6()
       
        # create datagram endpoints
        handler = self._datagram_received
        self._listen_ipv4 = loop.create_datagram_endpoint(lambda:
                ServerProtocol(handler), sock=ipv4_socket)
        self._transport_ipv4, self._protocol_ipv4 = loop.run_until_complete(self._listen_ipv4)

        self._listen_ipv6 = loop.create_datagram_endpoint(lambda:
                ServerProtocol(handler), sock=ipv6_socket)
        self._transport_ipv6, self._protocol_ipv6 = loop.run_until_complete(self._listen_ipv6)

        self._loop.call_later(5, self._print_task)

    def _datagram_received(self, data, addr):
        ip, port = addr[0], addr[1]
        message = Message()
        message.parse(data)

        logger.info('Message received')
        logger.info('ip: {}, port: {}'.format(ip, port))
        logger.info(message)
        if ip not in self._hosts:
            self._hosts.append(ip)

    def _print_task(self):
        self._loop.call_later(5, self._print_task)
        logger.info('Time: {}'.format(time.strftime('%Y-%m-%d, %H:%M:%S')))
        logger.info('Hosts: {}'.format(str(self._hosts)))

