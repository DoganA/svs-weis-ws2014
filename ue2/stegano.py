#!/usr/bin/python2.7
# encoding: utf-8

import logging
import binascii
from helper import *
from copy import copy
from PIL import Image

def hide_data_in_image(img, data_as_bytearray):
        logging.debug(">> hide_data_in_image()")
        logging.debug("data_as_bytearray: %s",
            binascii.hexlify(data_as_bytearray))
        img_input_as_bytes = image_to_bytearray(img)
        img_output_as_bytes = copy(img_input_as_bytes)

        # Check if image has enough pixels to hide the text
        # One byte == one character (assume ascii)
        # --> 8 b (1 bit per 1 byte) for hide
        if len(data_as_bytearray) * 8 < len(img_input_as_bytes):
            for i in range(len(data_as_bytearray) * 8):
                bit = get_specific_bit(data_as_bytearray[i / 8], 7 - i % 8)
                if bit:
                    img_output_as_bytes[i] = img_output_as_bytes[i] | 1
                else:
                    img_output_as_bytes[i] = img_output_as_bytes[i] & ~1
            #print "Image data with text as bytearray:"
            #pretty_print_bytearray(img_output_as_bytes)
            logging.debug("<< hide_data_in_image()")
            return Image.frombuffer(img.mode, img.size,
                buffer(img_output_as_bytes), 'raw', img.mode, 0, 1) 
        else:
            raise ValueError("Image is to small to hide the text.")
