import argparse
import socket
import random
import os
import string
import sys
import base64
import hashlib
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utils import *

def network_interface(server_port):

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)         
	s.bind(("localhost", int(server_port))) 
	s.listen(20)
	print("Server is running...")

	while True:

		try:
			c, addr = s.accept()    
			data = c.recv(1024).decode('utf-8')
			command_processor(data)

		except (KeyboardInterrupt, SystemExit):

			print("Server has closed")
			sys.exit(1)

def command_processor(command):



def update_password_file():

	if !os.path.isdir("serverkeys"):

		os.mkdir("server")

	else:

		f1 = open("serverpub.txt", "wb")
		f2 = open("serverpriv.txt", "wb")



def main():

	parser = argparse.ArgumentParser()
	parser.add_argument(type=str, dest='port_number')
	args = parser.parse_args()

	public_key, private_key = update_password_file()

	network_interface(args.port_number)


if __name__ == '__main__':
    logger = None
    try:
        main()
    except Exception:
        if logger:
            logger.exception('Exception in %s', os.path.basename(__file__))
        else:
            raise