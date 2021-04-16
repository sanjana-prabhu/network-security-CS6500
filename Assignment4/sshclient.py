import argparse
import socket
import random
import os
import string
import sys
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from utils import *

def user_input_interface(port_number, username, session_key):

	print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	print("| Welcome! You may enter any of the following commands at the Client Prompt. |")
	print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	print("|        pwd             |              prints the current working directory |")
	print("|    cd directory        |      changes the directory to the directory given |") 
	print("|        ls              |       lists the contents of the current directory |")  
	print("| cp filename dir1 dir2  | copies the file called filename from dir1 to dir2 |")
	print("| mv filename dir1 dir2  |  moves the file called filename from dir1 to dir2 |")
	print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

	while True:

		try:
			command = input("<Client Prompt>")
			network_interface(command, port_number, username, session_key)

		except (KeyboardInterrupt, SystemExit):

			print("Client has logged out.")
			sys.exit(1)
		

def network_interface(command, port_number, username, session_key):

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("localhost", int(port_number)))
	
	encr_message = encrypt(command, session_key)
	s.sendall(b'|302|'+encr_message)

	data = s.recv(1024)
	data = decrypt(data, session_key).decode('utf-8')
	if data=='Logged out.':
		sys.exit(1)
	print(data)
	s.close()


def connect_to_server(ip, port_number, username):

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, int(port_number)))
	message = '|300|'
	s.sendall(bytes(message, 'utf-8'))
	data = s.recv(1024) 
	f = open('server_pub.txt', 'wb')
	f.write(data)
	f.close()
	authenticate_to_server(s, port_number, username)


def authenticate_to_server(s, port_number, username):

	session_key = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(32))
	password = input("Enter the password")
	passphrase = hashlib.md5(password.encode('utf-8')).digest()
	message = bytes(username,'utf-8') + passphrase + bytes(session_key, 'utf-8')
	public_key = RSA.import_key(open("server_pub.txt").read())
	cipher_rsa = PKCS1_OAEP.new(public_key)
	message = cipher_rsa.encrypt(message)

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("localhost", int(port_number)))
	s.sendall(b'|301|'+message)
	data = s.recv(1024)
	s.close()

	if data.decode('utf-8')=='OK':
		print("Successfully authenticated to server...")
		user_input_interface(port_number, username, session_key)
	else:
		print("Authentication failed!")


def main():

	parser = argparse.ArgumentParser()
	parser.add_argument(type=str, dest='ip')
	parser.add_argument(type=str, dest='port_number')
	parser.add_argument(type=str, dest='client_name')
	args = parser.parse_args()

	connect_to_server(args.ip, args.port_number, args.client_name)


if __name__ == '__main__':
    logger = None
    try:
        main()
    except Exception:
        if logger:
            logger.exception('Exception in %s', os.path.basename(__file__))
        else:
            raise