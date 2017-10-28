# -*- coding:utf-8 -*-

__author__ = 'Alexander Rüedlinger'

import binascii


def unhexlify_string(hexstr):
    hexstr = hexstr.replace(' ', '').replace('\n', '').replace('\r', '')
    return binascii.unhexlify(hexstr)

def py3_to_int(v):
    if type(v) is str:
        return ord(v)
    elif type(v) is bytes:
        return ord(v)
    else:
        return v

def py3_find_pos(data, c):
    return data.find(c.encode('utf-8'))

def py3_labels_to_string(labels):
    return b".".join(labels).decode('utf-8')
