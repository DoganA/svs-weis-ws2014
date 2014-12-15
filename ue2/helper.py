#!/usr/bin/python2.7
# encoding: utf-8

import logging
from PIL import Image

def image_to_bytearray(img):
    """Converts the contents of an image to bytearray.

    Args:
        image (PIL): image form which to get the contents

    Returns:
        bytearray (bytearray): Contents of image as bytearray
    """
    logging.debug(">> image_to_bytearray()")
    img_input_data = img.getdata()
    logging.debug("Number of pixels in image: %d",
        len(list(img_input_data)))
    result = []
    for pixel in img_input_data:
        for rgb_channel in pixel:
            result.append(rgb_channel)
    return bytearray(result)

def get_specific_bit(byte, bit_num):
    """Get specific bit of a byte

    Args:
        byte (byte): byte
        bit_num (int): bit number to get from byte (zero indexed)

    Returns
        specific bit (boolean): the value of the bit at bit_num in byte
    """
    return (byte & (1 << bit_num)) != 0

def pretty_print_bytearray(byte_array):
    for i in range(len(byte_array)):
        if i != 0 and i % 12 == 0:
            print "" # print new line
        print bin(byte_array[i])[2:].zfill(8),
    print "" # print new line
