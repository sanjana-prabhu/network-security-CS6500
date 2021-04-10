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

def connect_to_server(port_number):

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("localhost", int(port_number)))
	data = s.recv(1024) 
	server_pubkey = data.decode('utf-8')
	f = open('server_pub.txt', 'wb')
	f.write(server_pubkey)

	s.close()

def authenticate_to_server(port_number, username, database):

	session_key = os.random(32)
	passphrase = database[username]
	message = username + passphrase + session_key

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("localhost", int(port_number)))
	s.sendall(bytes(message, 'utf-8'))

def main():

	parser = argparse.ArgumentParser()
	parser.add_argument(type=str, dest='port_number')
	parser.add_argument(type=str, dest='client_name')
	args = parser.parse_args()

	pwd1 = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(16))
	pwd2 = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(16))
	pwd3 = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(16))

	database = {'sanjana1': pwd1, 'sanjana2': pwd2, 'sanjana3': pwd3}

	connect_to_server(args.port_number)

	authenticate_to_server(args.port_number, args.client_name, database)



if __name__ == '__main__':
    logger = None
    try:
        main()
    except Exception:
        if logger:
            logger.exception('Exception in %s', os.path.basename(__file__))
        else:
            raise