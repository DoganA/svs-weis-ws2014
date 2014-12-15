#!/usr/bin/python2.7
# encoding: utf-8

import sys, os, logging
from PIL import Image
from argparse import ArgumentParser
from stegano import hide_data_in_image
from helper import image_to_bytearray, pretty_print_bytearray

def main(argv=None):

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])

    logging.basicConfig(level=logging.ERROR)

    try:
        parser = ArgumentParser(
            description="Hide contents of a text-file in an image."
        )
        parser.add_argument(
            dest="file",
            help="text file to hide",
            metavar="file",
            type=str,
            nargs="?"
        )
        parser.add_argument(
            dest="image",
            help="image (.bmp)",
            metavar="image",
            nargs="?"
        )

        # Process arguments
        args = parser.parse_args()
        args_file = args.file
        args_img = args.image

        # Process text file
        text_file = open(args_file, 'r')
        text = text_file.read()
        text_file.close()

        print "Text to hide is: %s" % text
        text_as_bytes = bytearray(text)
        print "Text as bytearray:"
        pretty_print_bytearray(list(text_as_bytes))
        print "Number of bytes in text: %d" % len(text_as_bytes)

        # Process the image
        img_input = Image.open(args_img, 'r')
        img_input_as_bytes = image_to_bytearray(img_input)

        logging.info("Image as bytearray: %s", list(img_input_as_bytes))

        img_with_text = hide_data_in_image(img_input, text_as_bytes)
        img_with_text.save(args_img + ".ste", 'bmp')
        print "Successfully wrote new image. Yeah!"
        return 0
    except Exception as excep:
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(excep) + "\n")
        sys.stderr.write(indent + "  for help use --help" + "\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
