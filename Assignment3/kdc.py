import socket
import random
import string
import os
import argparse
import base64
import hashlib
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utils import *

def register_client(c, data, f):

	'''
	registers the client by storing its details in the password file
	c : TCP connection with the client
	data : data sent by the client for registration
	f : password file

	'''

	ip = (data[5:21]).decode('utf-8').strip('..')
	port_num = (data[21:29]).decode('utf-8').strip('.')
	master_key = (data[29:41]).decode('utf-8')
	client_name = (data[41:53]).decode('utf-8').strip('.')
	salt = client_name + master_key
	key_s = base64.b64encode(hashlib.md5(salt.encode('utf-8')).digest()).decode('utf-8')

	fp = open(f, 'r+')
	c.send(b'|302|'+bytes(client_name, 'utf-8'))
	c.close()

	checklist = []
	lines = fp.readlines()
	is_empty = len(lines)

	for line in lines:
		checklist.append(line[:len(client_name)+1])

	if ':'+client_name in checklist:
		lines[checklist.index(':'+client_name)] = ':' + client_name + ':' + ip + ':' + port_num + ':' + key_s+'\n'
		fp.close()
		os.remove(f)
		fp = open(f, 'w')
		for line in lines:
			fp.write(line)
	elif is_empty==0:
		fp.write(':' + client_name + ':' + ip + ':' + port_num + ':' + key_s+'\n')
	else:
		fp.write(':' + client_name + ':' + ip + ':' + port_num + ':' + key_s+'\n')
	fp.close()


def send_key(c, data, pwdfile):

	'''
	sends a session key for client to client communication to
	the client requesting for the key
	c : TCP connection with the client
	data : data sent by the client for key request
	f : password file
	returns client name in order to update output file/KDC log

	'''

	fp = open(pwdfile, 'r')

	encrypted_data = data[5:69]
	client_name = (data[69:81]).decode('utf-8').strip('.')
	iv_s = hashlib.md5(client_name.encode('utf-8')).digest()

	checklist = [] # gets sender data from pwd file
	lines = fp.readlines()
	for line in lines:
		checklist.append(line[:len(client_name)+1])
	l = lines[checklist.index(':'+client_name)]
	master_key_client = base64.b64decode(l[len(l)-25:len(l)-1])
	port_num_sender = l[len(client_name)+12:len(client_name)+17]
	ip_sender = l[len(client_name)+2:len(client_name)+11]
	req_message = unpad(decrypt(encrypted_data, master_key_client, iv_s))
	receiver_name = req_message[12:24].decode('utf-8').strip('.')

	checklist = [] # gets receiver data from pwd file
	for line in lines:
		checklist.append(line[:len(receiver_name)+1])
	l = lines[checklist.index(':'+receiver_name)]
	master_key_receiver = base64.b64decode(l[len(l)-25:len(l)-1])
	port_num_receiver = l[len(receiver_name)+12:len(receiver_name)+17]
	ip_receiver = l[len(receiver_name)+2:len(receiver_name)+11]
	iv_r = hashlib.md5(receiver_name.encode('utf-8')).digest()

	message_i = '|306|'
	session_key_c2c = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(16))
	iv = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(16))
	ticket_s = session_key_c2c + iv + req_message.decode('utf-8') + ip_receiver + port_num_receiver
	ticket_r = session_key_c2c + iv + req_message.decode('utf-8') + ip_sender + port_num_sender

	message = message_i + encrypt(ticket_s, master_key_client, iv_s).decode('utf-8') + encrypt(ticket_r, master_key_receiver, iv_r).decode('utf-8')

	c.sendall(bytes(message, 'utf-8'))
	c.close()

	return client_name


def enable_KDC(port, outputfile, pwdfile):

	'''
	function to enable to KDC to listen on the specified IP and port number
	port : KDC port number
	outputfile : file to store the diagnostic outputs from the KDC
	pwdfile : file to store password details of the clients

	'''

	os.remove(outputfile) # overwrites previous log
	fo = open(outputfile, 'a')
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)         

	s.bind(("localhost", int(port))) 
	s.listen(20)
	print("Starting TCP server to listen on port "+port+"...")
	print("Waiting for messages from clients...")
	print("Type Ctrl-C to finally quit.")

	while True:

		try:
			c, addr = s.accept()    
			data = c.recv(1024)
			tag = int((data[1:4]).decode('utf-8'))

			if tag==301:
				fo.write('Registration request received from client at '+str(addr[0])+':'+str(addr[1])+'\n')
				register_client(c, data, pwdfile)
			elif tag==305:
				client_name = send_key(c, data, pwdfile)
				fo.write("Secret key requested by client "+client_name)

		except (KeyboardInterrupt, SystemExit):

			print("KDC has closed, output log file is "+outputfile)
			sys.exit(1)


def main():

	parser = argparse.ArgumentParser()
	parser.add_argument('-p', type=str, dest='kdcport')
	parser.add_argument('-o', type=str, dest='outputfile')
	parser.add_argument('-f', type=str, dest='pwdfile')
	args = parser.parse_args()

	enable_KDC(args.kdcport, args.outputfile, args.pwdfile)

if __name__ == '__main__':
    logger = None
    try:
        main()
    except Exception:
        if logger:
            logger.exception('Exception in %s', os.path.basename(__file__))
        else:
            raise
