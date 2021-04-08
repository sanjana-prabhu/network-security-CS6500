import socket
import random
import string
import os
import argparse
import base64
import hashlib
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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

def register_client(c, data, f):

	ip = (data[5:21]).decode('utf-8').strip('..')
	port_num = (data[21:29]).decode('utf-8').strip('.')
	master_key = (data[29:41]).decode('utf-8')
	client_name = (data[41:53]).decode('utf-8').strip('.')

	#print(ip, port_num, master_key, client_name,'check')

	fp = open(f, 'r+')
	c.send(b'|302|'+bytes(client_name, 'utf-8'))
	c.close()

	checklist = []
	lines = fp.readlines()
	is_empty = len(lines)

	for line in lines:
		checklist.append(line[:len(client_name)+1])

	if ':'+client_name in checklist:
		lines[checklist.index(':'+client_name)] = ':' + client_name + ':' + ip + ':' + port_num + ':' + master_key+'\n'
		fp.close()
		os.remove(f)
		fp = open(f, 'w')
		for line in lines:
			fp.write(line)
	elif is_empty==0:
		fp.write(':' + client_name + ':' + ip + ':' + port_num + ':' + master_key+'\n')
	else:
		fp.write(':' + client_name + ':' + ip + ':' + port_num + ':' + master_key+'\n')
	fp.close()

def send_key(c, data, pwdfile):

	fp = open(pwdfile, 'r')

	encrypted_data = data[5:69]
	client_name = (data[69:81]).decode('utf-8').strip('.')
	iv_s = hashlib.md5(client_name.encode('utf-8')).digest()

	checklist = []#get sender data from pwd file
	lines = fp.readlines()
	for line in lines:
		checklist.append(line[:len(client_name)+1])
	l = lines[checklist.index(':'+client_name)]
	master_key_client = l[len(l)-13:len(l)-1]
	port_num_sender = l[len(client_name)+12:len(client_name)+17]
	ip_sender = l[len(client_name)+2:len(client_name)+11]

	#print(master_key_client, port_num_sender, ip_sender,'pwd')
	

	salt = client_name + master_key_client
	key_s = hashlib.md5(salt.encode('utf-8')).digest()
	# print(salt, "salt")
	#print(encrypted_data, key_s, iv_s,"ch1")
	req_message = unpad(decrypt(encrypted_data, key_s, iv_s))
	#print(req_message.decode('utf-8'),"mess")
	receiver_name = req_message[12:24].decode('utf-8').strip('.')
	#print(req_message,"llllllllllll")

	checklist = []#get receiver data from pwd file
	for line in lines:
		checklist.append(line[:len(receiver_name)+1])
	l = lines[checklist.index(':'+receiver_name)]
	#print(l,"bob")
	master_key_receiver = l[len(l)-13:len(l)-1]
	salt = receiver_name + master_key_receiver
	key_r = hashlib.md5(salt.encode('utf-8')).digest()

	port_num_receiver = l[len(receiver_name)+12:len(receiver_name)+17]
	ip_receiver = l[len(receiver_name)+2:len(receiver_name)+11]
	iv_r = hashlib.md5(receiver_name.encode('utf-8')).digest()

	#print(master_key_receiver, port_num_receiver, ip_receiver,"sowjdwhd")
	message_i = '|306|'

	session_key_c2c = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(16))

	iv = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(16))

	ticket_s = session_key_c2c + iv + req_message.decode('utf-8') + ip_receiver + port_num_receiver

	ticket_r = session_key_c2c + iv + req_message.decode('utf-8') + ip_sender + port_num_sender

	message = message_i + encrypt(ticket_s, key_s, iv_s).decode('utf-8') + encrypt(ticket_r, key_r, iv_r).decode('utf-8')

	#print(len(encrypt(ticket_s, key_s, iv_s).decode('utf-8')),"Length1", encrypt(ticket_s, key_s, iv_s).decode('utf-8'))
	#print(len(encrypt(ticket_r, key_r, iv_r).decode('utf-8')),"Length2")

	#print(session_key_c2c, iv, ip_receiver, port_num_receiver,"checkiidii")

	c.sendall(bytes(message, 'utf-8'))
	c.close()

	return client_name

def enable_KDC(port, outputfile, pwdfile):

	os.remove(outputfile)#overwrite previous session
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
			#print(data,"kop")
			tag = int((data[1:4]).decode('utf-8'))

			if tag==301:
				fo.write('Registration request received from client at '+str(addr[0])+':'+str(addr[1])+'\n')
				register_client(c, data, pwdfile)
			elif tag==305:
				client_name = send_key(c, data, pwdfile)
				fo.write("Secret key requested by client "+client_name)

		except (KeyboardInterrupt, SystemExit):

			print("Script done, output file is "+outputfile)
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
