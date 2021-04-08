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


def register_with_KDC(client_name, kdcip, kdcport, key, client_port_num):

	message = '|301|'
	kdcip_modified = kdcip + (16-len(kdcip))*'.'
	clientport_modified = client_port_num + (8-len(client_port_num))*'.'
	client_name_modified = client_name + (12-len(client_name))*'.'
	message = message + kdcip_modified + clientport_modified + key + client_name_modified 

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	s.connect((kdcip, int(kdcport)))
	s.sendall(bytes(message, 'utf-8'))
	data = s.recv(1024)
	s.close()
	print("Contacts KDC and registers...")

def send_message_to_client(data, master_key, message, client_name):

	encrypted_ticket_s = data[5:133].decode('utf-8') #length of 306 ticket1 is 96
	#print(encrypted_ticket_s,"check with Length1")
	salt = client_name + master_key
	key = hashlib.md5(salt.encode('utf-8')).digest() # generating 128 bit key from passphrase
	iv = hashlib.md5(client_name.encode('utf-8')).digest()
	decrypted_ticket = unpad(decrypt(encrypted_ticket_s, key, iv))
	secret_key = decrypted_ticket[:16]
	iv_s = decrypted_ticket[16:32]
	ip_b = decrypted_ticket[68:77].decode('utf-8')
	port_b = decrypted_ticket[77:82].decode('utf-8')

	#print(secret_key, iv, ip_b, port_b,"checkiiii")

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip_b, int(port_b)))
	s.sendall(b'|309|'+data[133:])
	s.close()

	encrypted_message = encrypt(message, secret_key, iv_s)

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip_b, int(port_b)))
	s.sendall(encrypted_message)

	s.close()

def key_request(client_name, master_key, kdcip, kdcport, receiver_name, inputfile):

	message_i = '|305|'
	client_name_modified = client_name + (12-len(client_name))*'.'
	receiver_name_modified = receiver_name + (12-len(receiver_name))*'.'
	nonce = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(12))
	ticket = client_name_modified+receiver_name_modified+nonce
	#print(len(ticket),"k")
	salt = client_name + master_key
	#print(salt,'salt')
	key = hashlib.md5(salt.encode('utf-8')).digest() # generating 128 bit key from passphrase
	iv = hashlib.md5(client_name.encode('utf-8')).digest()

	encrypted_ticket = encrypt(ticket, key, iv)
	# print(ticket,"mess")
	# print(encrypted_ticket,'l2')
	# print(len(encrypted_ticket),"l1")
	# print(client_name_modified,'l3')
	# print(iv,'l4')
	message = message_i + encrypted_ticket.decode('utf-8') + client_name_modified
	# print(salt,"salt")
	# print(encrypted_ticket, key, iv,"ch1")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((kdcip, int(kdcport)))
	s.sendall(bytes(message, 'utf-8'))
	data = s.recv(1024) #contains 306 message
	s.close()
	print("Contacts KDC for secret key...")

	tag = int(data[1:4].decode('utf-8'))
	if tag==306:
		message = inputfile.read()
		send_message_to_client(data, master_key, message, client_name)
		print("Quits after sending the file to",receiver_name)
	


def pad(s, block_size):

	return s + (block_size - len(s) % block_size)*chr(block_size - len(s) % block_size)

def unpad(s):

	return s[:-ord(s[len(s)-1:])]

def encrypt(message, key, iv):

	message = pad(message, 16)
	message = bytes(message, 'utf-8')
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
	encryptor = cipher.encryptor()
	ciphertext = base64.b64encode(encryptor.update(message) + encryptor.finalize())

	return ciphertext

def decrypt(encrypted_message, key, iv):

	cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
	decryptor = cipher.decryptor()
	ciphertext = base64.b64decode(encrypted_message)

	return decryptor.update(ciphertext) + decryptor.finalize()

def receive_message(s, port, ip, outputfile, encr_out_file, master_key, client_name):

	s.listen(5)
	fo = open(outputfile, 'w')
	
	c, addr = s.accept()
	data = c.recv(1024)
	tag = int((data[1:4]).decode('utf-8'))
	#print(tag,'ppp')

	if tag==309:
		encrypted_ticket = data[5:]
		salt = client_name + master_key
		key = hashlib.md5(salt.encode('utf-8')).digest() # generating 128 bit key from passphrase
		iv = hashlib.md5(client_name.encode('utf-8')).digest()
		decrypted_ticket = unpad(decrypt(encrypted_ticket, key, iv))
		secret_key = decrypted_ticket[:16]
		iv_s = decrypted_ticket[16:32]
		sender_name = decrypted_ticket[32:44].decode('utf-8').strip('.')
		ip_a = decrypted_ticket[68:77].decode('utf-8')
		port_a = decrypted_ticket[77:82].decode('utf-8')

		#print(secret_key, iv, ip_a, port_a,"checkiiii")
		c2, addr = s.accept()
		data = c2.recv(1024)
		message = unpad(decrypt(data, secret_key, iv_s))
		encr_out_file.write(data)
		fo.write(message.decode('utf-8'))
		print("Quits after receiving the file from",sender_name)

def main():

	parser = argparse.ArgumentParser()
	parser.add_argument('-n', type=str, dest='client_name')
	parser.add_argument('-m', type=str, dest='action')
	parser.add_argument('-o', type=str) #either receiver or encrypted output
	parser.add_argument('-i', type=argparse.FileType('r'), dest='inputfile')
	parser.add_argument('-a', type=str, dest='kdcip')
	parser.add_argument('-p', type=str, dest='kdcport')
	parser.add_argument('-s', type=argparse.FileType('wb'), dest='outenc')

	args = parser.parse_args()

	if args.action=='S':

		master_key_s = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(12))
		client_port_num = ''.join(random.choice(string.digits) for i in range(5))
		port = int(client_port_num)%65536
		if port<10000:
			port = port + 10000
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
		s.bind(("localhost", port))

		register_with_KDC(args.client_name, args.kdcip, args.kdcport, master_key_s, str(port))
		print("Sleeps for 15 seconds...")
		time.sleep(5)
		key_request(args.client_name, master_key_s, args.kdcip, args.kdcport, args.o, args.inputfile)

	elif args.action=='R':

		master_key_r = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(12))
		client_port_num = ''.join(random.choice(string.digits) for i in range(5))
		port = int(client_port_num)%65536 
		if port<10000:
			port = port + 10000  

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      
		s.bind(("localhost", port))
		register_with_KDC(args.client_name, args.kdcip, args.kdcport, master_key_r, str(port))
		print("Sleeps for 15 seconds...")
		time.sleep(5)
		receive_message(s, port, args.kdcip, args.o, args.outenc, master_key_r, args.client_name)



if __name__ == '__main__':
    logger = None
    try:
        main()
    except Exception:
        if logger:
            logger.exception('Exception in %s', os.path.basename(__file__))
        else:
            raise
