# -*- coding:utf-8 -*-
from aiomdns import protocol


def test_create_socket_ipv4():
    socket = protocol.create_socket_ipv4()
    assert socket is not None

def test_create_socket_ipv6():
    socket = protocol.create_socket_ipv6()
    assert socket is not None
