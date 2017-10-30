# -*- coding:utf-8 -*-
import aiomdns
from aiomdns import util
import sys


def test_unhexlify_string():
    hexstr = '00 84'
    data = util.unhexlify_string(hexstr)
    assert data == b'\x00\x84'


def test_py3_labels_to_string():
    py3_labels = [b'test', b'_tcp', b'local']
    name = util.py3_labels_to_string(py3_labels)
    assert name == 'test._tcp.local'


def test_py3_find_pos1():
    data = b'key=value'
    assert util.py3_find_pos(data, '=') == 3


def test_py3_find_pos2():
    data = b'key==value'
    assert util.py3_find_pos(data, '=') == 3


def test_py3_to_int1():
    data = b'a'
    assert util.py3_to_int(data) == 97


def test_py3_to_int2():
    data = 'a'
    assert util.py3_to_int(data) == 97


def test_py3_to_int3():
    data = 97
    assert util.py3_to_int(data) == 97
