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
from shutil import copyfile

def network_interface(s, session_key, server_port, username, working_dir): 

	while True:

		try:
			c, addr = s.accept()
			data = c.recv(1024)
			plaintext = decrypt(data, session_key).decode('utf-8')
			message = command_processor(plaintext, s, server_port, username)
			encr_message = encrypt(message, session_key)
			c.sendall(b'|302|'+encr_message)
			if message=="Logged out.":
				start_server(s, server_port, working_dir) # restart server if client logs out

		except (KeyboardInterrupt, SystemExit):

			sys.exit(1)


def initiate_client_connection(c, data):

	if data[1:4].decode('utf-8')=='300':

		f = open("serverkeys/serverpub.txt", "rb")
		public_key = f.read()
		c.sendall(public_key)
		return 0, 0

	elif data[1:4].decode('utf-8')=='301':

		rsa_encrypted_data = data[5:]

		private_key = RSA.import_key(open("serverkeys/serverpriv.txt").read())
		cipher_rsa = PKCS1_OAEP.new(private_key)
		message = cipher_rsa.decrypt(rsa_encrypted_data)
		username = message[:8].decode('utf-8')
		passphrase = message[8:24]
		session_key = message[24:].decode('utf-8')

		f = open('UserCredentials/'+ username+'.txt', 'rb')
		salt_pwd = f.readlines()[1]

		iv = base64.b64decode(salt_pwd[:24])
		ct = base64.b64decode(salt_pwd[24:])
		cipher = AES.new(passphrase, AES.MODE_CBC, iv)
		pt = cipher.decrypt(ct)
	
		if pt==b'0'*16:
			message = "OK"
			c.sendall(bytes(message, 'utf-8'))
			print(username+" has successfully authenticated to server...")
			return username, session_key
		else:
			message = "NOK"
			c.sendall(bytes(message, 'utf-8'))
			f.close()
			return username, -1


def command_processor(plaintext, s, port_number, username):

	if plaintext[:3]=='pwd':

		message = 'The current working directory is '+os.getcwd()

	elif plaintext[:2]=='ls':

		s = os.listdir()
		message = ' '.join(map(str, s))
		
	elif plaintext[:2]=='cd':

		commandlist = plaintext.split(' ')
		if len(commandlist)==1:
			pathname = '/'
		else:
			pathname = commandlist[1]
		try:
			os.chdir(pathname)
		except FileNotFoundError:
			return 'No directory called '+pathname+' exists.'
		message = 'The current working directory has been changed to '+os.getcwd()
		
	elif plaintext[:2]=='mv':

		commandlist = plaintext.split(' ')
		if len(commandlist)!=4:
			return "Incorrect command!"
		filename = commandlist[1]
		src = commandlist[2]
		dest = commandlist[3]
		source_path, dest_path = path_convert(src, dest, filename)
		try:		
			os.rename(source_path+filename, dest_path+filename)
		except FileNotFoundError:
			return 'The given path does not exist!'
		message = "File "+filename+" has been moved from "+source_path+" to "+dest_path
		
	elif plaintext[:2]=='cp':

		commandlist = plaintext.split(' ')
		if len(commandlist)!=4:
			return "Incorrect command!"
		filename = commandlist[1]
		src = commandlist[2]
		dest = commandlist[3]
		source_path, dest_path = path_convert(src, dest, filename)
		try:
			copyfile(source_path+filename, dest_path+filename)
		except FileNotFoundError:
			return 'The given path does not exist!'
		message = "File "+filename+" has been copied from "+source_path+" to "+dest_path
		
	elif plaintext[:6]=='logout':

		print(username+" has logged out.")
		message = "Logged out."

	else:
		return "Incorrect command!"

	return message


def update_password_file(): # creates server's pub and priv keys

	if not os.path.isdir("serverkeys"):

		os.mkdir("serverkeys")

	key = RSA.generate(1024)
	private_key = key.export_key()
	f = open("serverkeys/serverpriv.txt", "wb")
	f.write(private_key)
	f.close()

	public_key = key.publickey().export_key()
	f = open("serverkeys/serverpub.txt", "wb")
	f.write(public_key)
	f.close()


def update_user_database():

	if not os.path.isdir('UserCredentials'):

		os.mkdir('UserCredentials')

	pwd1 = 'abcdef'
	pwd2 = 'abcdef1212345678'
	pwd3 = '12345678abcdef12111'

	database = {'sanjana1': pwd1, 'sanjana2': pwd2, 'sanjana3': pwd3}

	for username in database:

		f = open('UserCredentials/'+ username + '.txt', 'wb')
		password = database[username]
		passphrase = hashlib.md5(password.encode('utf-8')).digest()

		message = b'0'*16
		cipher = AES.new(passphrase, AES.MODE_CBC)
		ct_bytes = cipher.encrypt(message)
		iv = base64.b64encode(cipher.iv)
		ct = base64.b64encode(ct_bytes)
		username = bytes(username+'\n', 'utf-8')

		f.write(username)
		f.write(iv + ct)
		f.close()


def get_session_key(s):

	c, addr = s.accept()    
	data = c.recv(1024)
	session_key = initiate_client_connection(c, data) # sends public key

	c, addr = s.accept()
	data = c.recv(1024)
	session_key = initiate_client_connection(c, data) # gets the session key, authenticates client

	return session_key


def start_server(s, port_number, working_dir):

	os.chdir(working_dir) # restores working directory
	start = True
	while start:
		username, session_key = get_session_key(s) 
		if session_key==-1:
			start = True
		else:
			start = False # starts network interface if client is authenticated
	
	network_interface(s, session_key, port_number, username, working_dir)


def main():

	parser = argparse.ArgumentParser()
	parser.add_argument(type=str, dest='port_number')
	args = parser.parse_args()
	working_dir = os.getcwd()
	update_password_file()
	update_user_database()

	while True:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)         
			s.bind(("localhost", int(args.port_number))) 
			s.listen(20)
			print("Server is running...")
			start_server(s, int(args.port_number), working_dir)

		except (KeyboardInterrupt, SystemExit):

			print("Server has closed.")
			sys.exit(1)


if __name__ == '__main__':
    logger = None
    try:
        main()
    except Exception:
        if logger:
            logger.exception('Exception in %s', os.path.basename(__file__))
        else:
            raise