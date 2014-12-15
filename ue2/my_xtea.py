#!/usr/bin/python2.7
# encoding: utf-8

# Sites I used to get this work:
#   - http://www.kuno-kohn.de/crypto/crypto/modes.htm#CFB !!!
#   - http://de.wikipedia.org/wiki/Cipher_Feedback_Mode
#   - https://pypi.python.org/pypi/xtea/0.4.0
#   - http://de.wikipedia.org/wiki/Extended_Tiny_Encryption_Algorithm

import struct
import logging
from collections import deque
import binascii

def encrypt_cfb(key, data):
    logging.debug(">> encrypt_cfb()")
    logging.debug("Length data: %s", len(data))
    logging.debug("Type data: %s", type(data))
    shift_register = deque("12345678", 8)
    out = []
    fb = ''.join(shift_register)
    for byte in data:
        tx = encipher(fb, key)
        shift_register.append(chr(int(binascii.hexlify(tx[0]), 16) ^ byte))
        fb = ''.join(shift_register)
        out.append(chr(int(binascii.hexlify(tx[0]), 16) ^ byte))
    logging.debug("<< encrypt_cfb()")
    return "".join(out)

def decrypt_cfb(key, data):
    shift_register = deque("12345678", 8)
    out = []
    fb = ''.join(shift_register)
    for byte in data:
        tx = encipher(fb, key)
        shift_register.append(chr(byte))
        fb = ''.join(shift_register)
        out.append(chr(int(binascii.hexlify(tx[0]), 16) ^ byte))
    return "".join(out)

def encipher(block, key):
    delta = 0x9E3779B9L
    mask = 0xffffffffL
    block_sum = 0L
    v0, v1 = struct.unpack("!2L", block)
    k = struct.unpack("!4L", key)
    for i in range(32):
        v0 = (v0 + (((v1<<4 ^ v1>>5) + v1) ^ (block_sum + k[block_sum & 3]))) & mask
        block_sum = (block_sum + delta) & mask
        v1 = (v1 + (((v0<<4 ^ v0>>5) + v0) ^ (block_sum + k[block_sum>>11 & 3]))) & mask
    return struct.pack("!2L", v0, v1)
