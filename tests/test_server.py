# -*- coding:utf-8 -*-
import asyncio
import socket
import mock
from aiomdns.server import Server

def test_create_server():
    ipv4_socket = mock.Mock()
    ipv4_socket.type = socket.SOCK_DGRAM
    ipv4_socket.SOCK_DGRAM = socket.SOCK_DGRAM
    ipv4_socket.recv.return_value = ''

    ipv6_socket = mock.Mock()
    ipv6_socket.type = socket.SOCK_DGRAM
    ipv6_socket.SOCK_DGRAM = socket.SOCK_DGRAM
    ipv6_socket.recv.return_value = '' 
    
    loop = asyncio.get_event_loop()
    server = Server(loop, ipv4_socket, ipv6_socket)
    
