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

TO_ADDR = ""
FROM_ADDR = ""

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

def create_mime_text_msg(from_addr, to_addr, subject, msg):
	msg = MIMEText(msg)
	msg["From"] = email.utils.formataddr(("", from_addr))
	msg["To"] = email.utils.formataddr(("", to_addr))
	msg['Subject'] = subject
	return msg

def process_mailbox_for_keyexchange(mailbox):
	res_select, count_of_messages = mailbox.select("INBOX", True)
	res_search,  msgnums = mailbox.search(None, '(SUBJECT "My Public Key")')
	ids = msgnums[0]
	id_list = ids.split()

	if len(id_list) == 0:
		print "No keyexchange mail found."
		return None
	else:
		res_fetch, data = mailbox.fetch(id_list[-1], "(RFC822)")
		return email.message_from_string(data[0][1])

def main():
	logging.basicConfig(level=logging.DEBUG)
	rand_gen = random.SystemRandom()

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

	msg = create_mime_text_msg(TO_ADDR, FROM_ADDR, "My Public Key", public_key_b64)
	send_mail(FROM_ADDR, [TO_ADDR], msg)
	print "Send public key to {}".format(TO_ADDR)

	time.sleep(10)

	print SEPERATOR
	print "Bob"
	print SEPERATOR

	mail = imaplib.IMAP4_SSL(IMAP_SERVER["url"], IMAP_SERVER["port"])
	try:
		mail.login(USERNAME, PASSWORD)
	except imaplib.IMAP4.error:
		print "LOGIN FAILED!"

	mail_b = process_mailbox_for_keyexchange(mail)
	payload = base64.b64decode(mail_b.get_payload())
	print "Public key (JSON) from {} = {}".format(mail_b.get("From"), payload)
	public_key_a = json.loads(payload)

	b = rand_gen.randrange(0, public_key_a["p"])
	public_key_b = {"g" : g, "p" : p, "z" : gen_dhke_key(public_key_a["g"], b, public_key_a["p"])}
	public_key_b_as_json_str = json.dumps(public_key_b)
	print "Public Key B = {}".format(public_key_b_as_json_str)
	public_key_b_b64 = base64.b64encode(public_key_b_as_json_str)
	
	msg_b = create_mime_text_msg(TO_ADDR, FROM_ADDR,
		"Public Key Response", public_key_b_b64)
	send_mail(FROM_ADDR, TO_ADDR, msg_b)

	time.sleep(10)

	# GO ON
	b_key = process_key_response(mail)

	mail.logout()

	print "Key A = {}".format(gen_dhke_key(b_key["public_key"], a, p))


	#name = raw_input("Enter your name: ")
	#print name

if __name__ == "__main__":
	main()
