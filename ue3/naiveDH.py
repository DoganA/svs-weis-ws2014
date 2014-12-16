#!/usr/bin/python2.7

import hashlib, base64
import logging
import binascii
import random
import os, time
import json
import imaplib, smtplib
import email.utils
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from my_xtea import encrypt_cbc, decrypt_cbc

IMAP_SERVER = {"url" : "imap.gmx.net", "port" : 993}
SMTP_SERVER = {"url" : "mail.gmx.net", "port" : 587}

USERNAME = ""
PASSWORD = ""

TO_ADDR = USERNAME
FROM_ADDR = USERNAME

SEPERATOR = "-" * 79

def gen_dhke_key(base, exp, div):
	return base ** exp % div

def send_mail(from_addr, to_addrs, msg):
	server = smtplib.SMTP(SMTP_SERVER["url"], SMTP_SERVER["port"])
	server.starttls()
	server.ehlo()
	server.login(USERNAME, PASSWORD)
	server.sendmail(from_addr, to_addrs, msg.as_string())
	server.quit()

def get_mails_for_criteria(criteria, mailbox_name="INBOX"):
	server = imaplib.IMAP4_SSL(IMAP_SERVER["url"], IMAP_SERVER["port"])
	server.login(USERNAME, PASSWORD)
	server.select(mailbox_name, True)

	msgnums = server.search(None, criteria)[1]
	ids = msgnums[0]
	id_list = ids.split()
	msgs = []

	if len(id_list) == 0:
		print "No messages for criteria = {} found.".format(criteria)
	else:
		for mail_id in id_list:
			msg = server.fetch(mail_id, "(RFC822)")[1]
			msgs.append(email.message_from_string(msg[0][1]))

	server.logout()
	return msgs

def create_mime_text_msg(from_addr, to_addr, subject, msg):
	msg = MIMEText(msg)
	msg["From"] = email.utils.formataddr(("", from_addr))
	msg["To"] = email.utils.formataddr(("", to_addr))
	msg['Subject'] = subject
	return msg

def _message_payload_to_decoded_str(msg):
	return base64.b64decode(msg.get_payload())

def _remove_trailling_null_bytes_from_str(s):
	first_occur = s.find('\0')
	if first_occur != -1:
		return s[:first_occur]
	else:
		return s

def main():
	logging.basicConfig(level=logging.ERROR)
	rand_gen = random.SystemRandom()

	# Alice
	print SEPERATOR
	print "Alice"
	print SEPERATOR

	p = 23
	g = 5
	a = rand_gen.randrange(0, p)
	public_key = {"g" : g, "p" : p, "z" : gen_dhke_key(g, a, p)}

	public_key_as_json_str = json.dumps(public_key)
	print "Public key A (JSON) = {}".format(public_key_as_json_str)
	public_key_b64 = base64.b64encode(public_key_as_json_str)
	print "Public key A (base64) = {}".format(public_key_b64)

	msg = create_mime_text_msg(TO_ADDR, FROM_ADDR, "Key Exchange Request", public_key_b64)
	send_mail(FROM_ADDR, [TO_ADDR], msg)
	print "Send my public key to {}".format(TO_ADDR)

	time.sleep(10)

	# Bob
	print SEPERATOR
	print "Bob"
	print SEPERATOR

	key_exchange_mails = get_mails_for_criteria('(SUBJECT "Key Exchange Request")')
	print "Number of Key Exchange Request Mails = {}.".format(len(key_exchange_mails))

	mail_b = key_exchange_mails[0]
	payload_as_str = _message_payload_to_decoded_str(mail_b)
	print "Public key (JSON) from {} = {}".format(mail_b.get("From"), payload_as_str)
	public_key_a = json.loads(payload_as_str)

	b = rand_gen.randrange(0, public_key_a["p"])
	public_key_b = {"g" : g, "p" : p, "z" : gen_dhke_key(public_key_a["g"], b, public_key_a["p"])}
	public_key_b_as_json_str = json.dumps(public_key_b)
	public_key_b_b64 = base64.b64encode(public_key_b_as_json_str)

	secret_b = gen_dhke_key(public_key_a["z"], b, public_key_a["p"])
	print "My Secret = {}".format(secret_b)

	msg_b = create_mime_text_msg(TO_ADDR, FROM_ADDR, "Key Exchange Response", public_key_b_b64)
	send_mail(FROM_ADDR, TO_ADDR, msg_b)

	print "Send key exchange response to {}".format(TO_ADDR)
	time.sleep(10)
	
	# Alice
	
	print SEPERATOR
	print "Alice"
	print SEPERATOR
	
	key_exchange_response_mails = get_mails_for_criteria('(SUBJECT "Key Exchange Response")')
	print "Number of Key Exchange Response Mails = {}.".format(len(key_exchange_response_mails))
	
	mail_from_b = key_exchange_response_mails[0]
	payload_from_b = _message_payload_to_decoded_str(mail_from_b)
	print "Public key (JSON) from {} = {}".format(mail_from_b.get("From"), payload_from_b)
	public_key_from_b = json.loads(payload_from_b)

	print "My Secret = {}".format(gen_dhke_key(public_key_from_b["z"], a, p))

	msg = "lorem ipsum lorem"
	print "Message: {}".format(msg)
	msg_as_byte_array = bytearray(msg)

	# Block size 64 Bit (8 Byte)
	msg_as_byte_array += bytearray(8 - len(msg_as_byte_array) % 8)

	pw_as_byte_array = bytearray(hashlib.sha256(str(gen_dhke_key(public_key_from_b["z"], a, p))).digest()[:16])

	encrypted_msg = encrypt_cbc(str(pw_as_byte_array), msg_as_byte_array)
	print "Encrypted message (XTEA-CBC): {}".format(binascii.hexlify(encrypted_msg))
	encrypted_msg_base64 = base64.b64encode(encrypted_msg)
	print "Encrypted message (XTEA-CBC -> base64): {}".format(encrypted_msg_base64)

	msg_mail = create_mime_text_msg(TO_ADDR, FROM_ADDR, "My Message", encrypted_msg_base64)
	send_mail(FROM_ADDR, [TO_ADDR], msg_mail)

	print "Send message to {}".format(TO_ADDR)

	time.sleep(10)

	# Bob
	print SEPERATOR
	print "Bob"
	print SEPERATOR

	mail_new_message_a =  get_mails_for_criteria('(SUBJECT "My Message")')[0]
	message_a = _message_payload_to_decoded_str(mail_new_message_a)
	encrypted_msg_1 = message_a
	print "Encrypted message (base64 -> XTEA-CBC): {}".format(binascii.hexlify(encrypted_msg_1))
	decrypted_msg = decrypt_cbc(str(pw_as_byte_array), bytearray(encrypted_msg_1))
	print "Decrypted message: {}".format(_remove_trailling_null_bytes_from_str(decrypted_msg))

if __name__ == "__main__":
	main()
