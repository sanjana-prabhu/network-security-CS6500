import sys
import os
import hashlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

def decrypt(data, session_key):

	ciphertext = data[5:len(data)-27]
	tag = data[len(data)-27:len(data)-11]
	nonce = data[len(data)-11:len(data)]
	session_key = bytes(session_key, 'utf-8')
	cipher = AES.new(session_key, AES.MODE_CCM, nonce=nonce)
	cipher.update(b"header")
	plaintext = cipher.decrypt_and_verify(ciphertext, tag)
	return plaintext

def encrypt(message, session_key):

	header = b"header"
	data = bytes(message, 'utf-8')
	key = bytes(session_key, 'utf-8')
	cipher = AES.new(key, AES.MODE_CCM)
	cipher.update(header)
	ciphertext, tag = cipher.encrypt_and_digest(data)
	nonce = cipher.nonce

	return ciphertext+tag+nonce

def path_convert(src, dest, filename):

	if src=='../':
		source_path = os.path.dirname(os.getcwd())+'/'
	elif src=='/':
		source_path = os.getcwd()+'/'
	else:
		source_path = os.getcwd()+'/'+src
	if dest=='../':
		dest_path = os.path.dirname(os.getcwd())+'/'
	elif dest=='/':
		dest_path = os.getcwd()+'/'
	else:
		dest_path = os.getcwd()+'/'+dest

	return source_path, dest_path