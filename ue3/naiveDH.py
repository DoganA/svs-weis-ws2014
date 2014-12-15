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
PASSWORD = "

TO_ADDR = ""
FROM_ADDR = ""

def gen_dhke_key(base, exp, div):
	return base ** exp % div

def send_mail(from_addr, to_addrs, msg):
	server = smtplib.SMTP(SMTP_SERVER["url"], SMTP_SERVER["port"])
	server.starttls()
	server.ehlo()
	server.login(username, password)
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
	res_search,  msgnums = mailbox.search(None, '(SUBJECT "Crypto")')
	ids = msgnums[0]
	id_list = ids.split()

	if len(id_list) == 0:
		print "No keyexchange mail found."

	msgs = []

	for mail_id in id_list:
		res_fetch, data = mailbox.fetch(mail_id, "(RFC822)")
		msgs.append(email.message_from_string(data[0][1]))

	return msgs

def main():
	logging.basicConfig(level=logging.DEBUG)
	p = 49999
	rand_gen = random.SystemRandom()
	g = rand_gen.randrange(0, p)
	print "p = {}".format(p)
	print "g = {}".format(g)
	a = rand_gen.randrange(0, p)
	print "a = {}".format(a)
	public_key_a = gen_dhke_key(g, a, p)
	print "Public key A = {}".format(public_key_a)

	data_init_a = {"p" : p, "g" : g, "public_key" : public_key_a}
	data_string = json.dumps(data_init_a)
	print data_string

	data_b64 = base64.b64encode(data_string)
	print "Data (base64) = {}".format(data_b64)

	msg = create_mime_text_msg(TO_ADDR, FROM_ADDR, "Crypto-Key", data_b64)

	send_mail(FROM_ADDR, [TO_ADDR], msg)

	time.sleep(10)

	mail = imaplib.IMAP4_SSL(IMAP_SERVER["url"], IMAP_SERVER["port"])
	try:
		mail.login(USERNAME, PASSWORD)
	except imaplib.IMAP4.error:
		print "LOGIN FAILED!"

	mails_b = process_mailbox_for_keyexchange(mail)

	for msg in mails_b:
		payload = base64.b64decode(msg.get_payload())
		print payload
		#return json.loads(payload)


	print a_keys

	b = rand_gen.randrange(0, a_keys["p"])
	public_key_b = gen_dhke_key(a_keys["g"], b, a_keys["p"])

	print "Key B = {}".format(gen_dhke_key(a_keys["public_key"], b, a_keys["p"]))

	data_init_b = {"public_key" : public_key_b}
	data_string_b = json.dumps(data_init_b)
	print data_string_b

	data_b64_b = base64.b64encode(data_string_b)

	send_mail(FROM_ADDR, TO_ADDR, "Crypto-Key-Response", data_b64_b)

	time.sleep(10)

	b_key = process_key_response(mail)

	mail.logout()

	print "Key A = {}".format(gen_dhke_key(b_key["public_key"], a, p))


	#name = raw_input("Enter your name: ")
	#print name

if __name__ == "__main__":
	main()
