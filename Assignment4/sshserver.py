import argparse
import socket
import random
import os
import string
import sys
import base64
import hashlib
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from utils import *
from shutil import copyfile

def network_interface(server_port):

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)         
	s.bind(("localhost", int(server_port))) 
	s.listen(20)
	print("Server is running...")

	public_key = RSA.import_key(open("serverkeys/serverpub.txt").read())
	
	c, addr = s.accept()    
	data = c.recv(1024)
	session_key = initiate_client_connection(c, data) # sends public key

	c, addr = s.accept()
	data = c.recv(1024)
	session_key = initiate_client_connection(c, data) # gets the session key, authenticates client

	while True:

		try:
			c, addr = s.accept()
			data = c.recv(1024)
			plaintext = decrypt(data, session_key).decode('utf-8')
			message = command_processor(plaintext)
			encr_message = encrypt(message, session_key)
			c.sendall(b'|302|'+encr_message)

		except (KeyboardInterrupt, SystemExit):

			print("Server has closed")
			sys.exit(1)


def initiate_client_connection(c, data):

	if data[1:4].decode('utf-8')=='300':

		f = open("serverkeys/serverpub.txt", "rb")
		public_key = f.read()
		c.sendall(public_key)
		return 0

	elif data[1:4].decode('utf-8')=='301':

		rsa_encrypted_data = data[5:]
		private_key = RSA.import_key(open("serverkeys/serverpriv.txt").read())
		cipher_rsa = PKCS1_OAEP.new(private_key)
		message = cipher_rsa.decrypt(rsa_encrypted_data)
		username = message[:8].decode('utf-8')
		passphrase = message[8:24].decode('utf-8')
		passphrase = bytes(passphrase, 'utf-8')
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
			print("sent")
			return session_key
		else:
			message = "NOK"
			c.sendall(bytes(message, 'utf-8'))
			f.close()


def command_processor(plaintext):

	if plaintext=='pwd':

		message = 'The current working directory is '+os.getcwd()

	elif plaintext=='ls':

		s = os.listdir()
		message = ' '.join(map(str, s))
		
	elif plaintext[:2]=='cd':

		commandlist = plaintext.split(' ')
		pathname = commandlist[1]
		os.chdir(pathname)

		message = 'The current working directory has been changed to '+pathname
		
	elif plaintext[:2]=='mv':

		commandlist = plaintext.split(' ')
		filename = commandlist[1]
		src = commandlist[2]
		dest = commandlist[3]
		os.rename(os.getcwd()+'/'+src+filename, os.getcwd()+'/'+dest+filename)
		if dest=='/':
			dest = ''
		if src=='/':
			src = ''
		message = "File "+filename+" has been moved from "+os.getcwd()+'/'+src+" to "+os.getcwd()+'/'+dest
		
	elif plaintext[:2]=='cp':

		commandlist = plaintext.split(' ')
		filename = commandlist[1]
		src = commandlist[2]
		dest = commandlist[3]
		copyfile(os.getcwd()+'/'+src+filename, os.getcwd()+'/'+dest+filename)
		if dest=='/':
			dest = ''
		if src=='/':
			src = ''
		message = "File "+filename+" has been copied from "+os.getcwd()+'/'+src+" to "+os.getcwd()+'/'+dest
		
	elif plaintext=='logout':

		print("Client has logged out.")
		message = "Logged out."

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

	pwd1 = 'abcdef12abcdef12'
	pwd2 = 'abcdef1212345678'
	pwd3 = '12345678abcdef12'

	database = {'sanjana1': pwd1, 'sanjana2': pwd2, 'sanjana3': pwd3}

	for username in database:

		f = open('UserCredentials/'+ username + '.txt', 'wb')
		passphrase = bytes(database[username], 'utf-8')
		message = b'0'*16
		cipher = AES.new(passphrase, AES.MODE_CBC)
		ct_bytes = cipher.encrypt(message)
		iv = base64.b64encode(cipher.iv)
		ct = base64.b64encode(ct_bytes)
		# iv = base64.b64decode(iv)
		# ct = base64.b64decode(ct)
		# cipher = AES.new(passphrase, AES.MODE_CBC, iv)
		# pt = cipher.decrypt(ct)
		# print("The message was: ", pt)
		
		username = bytes(username+'\n', 'utf-8')
		f.write(username)
		f.write(iv + ct)
		# print(len(iv),"lenhth")
		f.close()




def main():

	parser = argparse.ArgumentParser()
	parser.add_argument(type=str, dest='port_number')
	args = parser.parse_args()

	update_password_file()
	update_user_database()

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