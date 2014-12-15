#!/usr/bin/python2.7
# encoding: utf-8

# Sites I used to get this work:
#   - http://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
#   - https://pypi.python.org/pypi/xtea/0.4.0
#   - http://de.wikipedia.org/wiki/Extended_Tiny_Encryption_Algorithm

import struct
import logging
from collections import deque
import binascii

def encrypt_cbc(key, data):
	logging.debug(">> encrypt_cbc()")
	logging.debug("Type data: %s", type(data))

	iv = "12345678"
	block_size = 8 # block size in bytes
	if len(data) % block_size == 0:
		out = [iv]
		for block_start in range(0, len(data), 8):
			logging.debug("Block start index: %d", block_start)

			block = data[block_start: block_start + 8]
			logging.debug("Block: %s", block)

			xored = xor_byte_array(block, bytearray(out[(block_start / 8)]))
			encrypted_block = encipher(xored, key)
			logging.debug("Encrypted block: %s", binascii.hexlify(encrypted_block))
			out.append(encrypted_block)
		out_as_str = "".join(out[1:]) # without iv
		logging.debug("Out: %s", binascii.hexlify(bytearray(out_as_str)))
		logging.debug("<< encrypt_cbc()")
		return out_as_str
	else:
		logging.error("Block size: %s", block_size)
		logging.error("Length data: %s", len(data))
		raise ValueError("Length of data must be a multiple of block size")

def decrypt_cbc(key, data):
	logging.debug(">> decrypt_cbc()")
	logging.debug("Type data: %s", type(data))
	logging.debug("Data: %s", binascii.hexlify(bytearray(str(data))))

	iv = "12345678"
	block_size = 8 # block size in bytes
	tmp_data = bytearray(iv) + data
	if len(tmp_data) % 8 == 0:
		out = []
		for block_start in range(8, len(tmp_data), 8):
			logging.debug("Block start index: %d", block_start)

			block = tmp_data[block_start: block_start + 8]
			logging.debug("Block: %s", binascii.hexlify(bytearray(str(block))))

			decrypted_block = decipher(block, key)
			xored = xor_byte_array(tmp_data[block_start - 8: block_start], bytearray(decrypted_block))
			out.append(str(xored))
		out_as_str = "".join(out)
		logging.debug("Out: %s", out_as_str)
		logging.debug("<< decrypt_cbc()")
		return out_as_str
	else:
		logging.error("Block size: %s", block_size)
		logging.error("Length data: %s", len(data))
		raise ValueError("Length of data must be a multiple of block size")

def encipher(block, key):
	delta = 0x9E3779B9L
	mask = 0xffffffffL
	block_sum = 0L
	v0, v1 = struct.unpack("!2L", block)
	k = struct.unpack("!4L", key)
	for i in range(32):
		v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (block_sum + k[block_sum & 3]))) & mask
		block_sum = (block_sum + delta) & mask
		v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (block_sum + k[block_sum >> 11 & 3]))) & mask
	return struct.pack("!2L", v0, v1)

def decipher(block, key):
	delta = 0x9E3779B9L
	mask = 0xffffffffL
	block_sum = (delta * 32) & mask
	v0, v1 = struct.unpack("!2L", block)
	k = struct.unpack("!4L",key)
	for i in range(32):
		v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (block_sum + k[block_sum >> 11 & 3]))) & mask
		block_sum = (block_sum - delta) & mask
		v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (block_sum + k[block_sum & 3]))) & mask
	return struct.pack("!2L", v0, v1)

def xor_byte_array(b1, b2):
	assert(len(b1) == len(b2))
	result = bytearray()
	for i in range(len(b1)):
		result.append(b1[i] ^ b2[i])
	return result
