#!/usr/bin/python2.7
# encoding: utf-8

import sys, os, logging
import hashlib, hmac
import binascii
from my_xtea import *
from argparse import ArgumentParser
from PIL import Image
from copy import copy
from stegano import hide_data_in_image
from helper import image_to_bytearray, get_specific_bit, pretty_print_bytearray

def check_hmac(mac_pw, data_as_bytearray):
    logging.debug(">> check_hmac()")
    logging.debug("data-length: %s", len(data_as_bytearray))
    logging.debug("data: %s", binascii.hexlify(data_as_bytearray))
    # Hash MAC-password
    mac_pw_hash_as_bytearray = bytearray(hashlib.sha256(mac_pw).digest())

    # Compute hmac from MAC-password and text from data
    text_from_data = data_as_bytearray[32:]
    logging.debug("text from data: %s", binascii.hexlify(text_from_data))

    hmac_text = hmac.new(mac_pw_hash_as_bytearray,
        text_from_data,
        hashlib.sha256).digest()

    logging.debug("HMAC for text: %s",
        hmac.new(mac_pw_hash_as_bytearray,
        text_from_data,
        hashlib.sha256).hexdigest()
    )
    logging.debug("HMAC from data: %s",
        binascii.hexlify(data_as_bytearray[:32]))
    logging.debug("HMACs are equal: %s",
        hmac_text == data_as_bytearray[:32])
    logging.debug("<< check_hmac()")
    # MAC are the first 32 bytes (SHA256)
    return hmac_text == data_as_bytearray[:32]

def encrypt(mac_pw, pw, text_to_hide):
    logging.debug(">> encrypt()")
    logging.debug("mac_pw: %s", mac_pw)
    logging.debug("pw: %s", pw)
    logging.debug("text_to_hide: %s", text_to_hide)

    # Hash MAC-password
    mac_pw_hash_as_bytearray = bytearray(hashlib.sha256(mac_pw).digest())
    # Use only the 128 significant bits of pw hash (1 Byte * 16 = 128 Bit)
    xtea_pw_as_bytearray = bytearray(hashlib.sha256(pw).digest()[:16])

    hmac_hash = hmac.new(mac_pw_hash_as_bytearray,
        bytearray(text_to_hide),
        hashlib.sha256).digest()

    # concatenate hmac_hash and text_to_hide
    concat_text_to_hide_as_bytearray = bytearray(hmac_hash) + bytearray(text_to_hide)

    logging.debug("HMAC for text to hide: %s",
        binascii.hexlify(bytearray(hmac_hash)))
    logging.debug("Length of hmac_hash bytearray: %s",
        len(bytearray(hmac_hash)))
    logging.debug("Length of text_to_hide bytearray: %s",
        len(bytearray(text_to_hide)))


    concat_text_to_hide_as_bytearray += bytearray(8)

    logging.debug("Total data: %s",
        binascii.hexlify(concat_text_to_hide_as_bytearray))
    logging.debug("Total length: %s", len(concat_text_to_hide_as_bytearray))
    #pretty_print_bytearray(concat_text_to_hide_as_bytearray)

    encrypted_data = encrypt_cfb(str(xtea_pw_as_bytearray), concat_text_to_hide_as_bytearray)
    
    logging.debug("Encrypted data: %s",
        binascii.hexlify(bytearray(encrypted_data)))
    #pretty_print_bytearray(bytearray(encrypted_data))
    logging.debug("<< encrypt()")
    return encrypted_data

def decrypt(mac_pw, pw, img):
    logging.debug(">> decrypt()")
    logging.debug("mac_pw: %s", mac_pw)
    logging.debug("pw: %s", pw)

    xtea_pw_as_bytearray = bytearray(hashlib.sha256(pw).digest()[:16])

    img_input_as_bytes = image_to_bytearray(img)

    encrypted_data_as_bytearray = bytearray()

    for i in range(0, len(img_input_as_bytes), 8):
        tmp_byte = 0x00
        for a_byte in img_input_as_bytes[i:i+8]:
            msb = get_specific_bit(a_byte, 0)
            tmp_byte = tmp_byte << 1
            tmp_byte += msb
        encrypted_data_as_bytearray.append(tmp_byte)

    logging.debug("Size of encrypted data bytearray: %s",
        len(encrypted_data_as_bytearray))
    logging.debug("Encrypted data: %s",
        binascii.hexlify(encrypted_data_as_bytearray))
    decrypted_data_as_bytearray = bytearray(decrypt_cfb(str(xtea_pw_as_bytearray), encrypted_data_as_bytearray))

    logging.debug("Decrypted data: %s",
        binascii.hexlify(decrypted_data_as_bytearray))

    count_nul = 0
    last_nul = -1
    for i in range(len(decrypted_data_as_bytearray)):
        if chr(decrypted_data_as_bytearray[i]) == '\0':
            count_nul += 1
        else:
            if count_nul > 0:
                count_nul -= 1
        if count_nul == 8:
            last_nul = i
            break

    if last_nul == -1:
        raise SystemError("No byte sequence found which indicates end of data.")

    logging.debug("<< decrypt()")
    # remove trailling NUL bytes -> Result: hmac and text
    return decrypted_data_as_bytearray[:last_nul - 7]

def main(argv=None):

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])

    logging.basicConfig(level=logging.DEBUG)

    try:
        args_parser = ArgumentParser(description="Encyrpt or decrypt message in image with authentication")
        subparsers = args_parser.add_subparsers(dest="which", help="which mode")

        # Parser for mode "encrypt"
        encrypt_parser = subparsers.add_parser("encrypt", help="encryption")
        encrypt_parser.add_argument("-m", required=True,
            dest="macpw", metavar="macpassword", help="mac-password")
        encrypt_parser.add_argument("-k", required=True,
            dest="pw", metavar="password", help="password")
        encrypt_parser.add_argument(dest="file", help="text file to hide",
            metavar="file", type=str, nargs='?')
        encrypt_parser.add_argument(dest="image", help="image (.bmp)",
            metavar="image", type=str, nargs='?')

        # Parser for mode "decrypt"
        decrypt_parser = subparsers.add_parser("decrypt", help="decryption")
        decrypt_parser.add_argument("-m", required=True, dest="macpw",
            metavar="macpassword", help="mac-password")
        decrypt_parser.add_argument("-k", required=True, dest="pw",
            metavar="password", help="password")
        decrypt_parser.add_argument(dest="image", help="image (.bmp.sae)",
            metavar="image", type=str, nargs='?')

        # Process arguments
        args = args_parser.parse_args()
        logging.debug("Parsed arguments: %s", args)

        if args.which == "encrypt":
            # Process text file
            text_file = open(args.file, 'r')
            text = text_file.read().strip('\n')
            text_file.close()
            print "Text to hide is: %s" % text
            text_as_bytes = bytearray(text)
            print "Number of bytes in text: %d" % len(text_as_bytes)

            encrypted_data = encrypt(args.macpw, args.pw, text)
            img_input = Image.open(args.image, 'r')
            encrypted_img = hide_data_in_image(img_input,
                bytearray(encrypted_data))
            encrypted_img.save(args.image + ".sae", 'bmp')
            print "Successfully wrote new image. Yeah!"
            return 0
        elif args.which == "decrypt":
            img_input = Image.open(args.image, 'r')
            decrypted_data = decrypt(args.macpw, args.pw, img_input)
            print "HMAC are equal: %s" % check_hmac(args.macpw, decrypted_data)
            print "Decrypted text: %s" % str(decrypted_data[32:])
            return 0
        else:
            raise Exception("What you want to do???")
    except Exception, e:
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help" + "\n")
        return 2

if __name__ == "__main__":
    sys.exit(main())
