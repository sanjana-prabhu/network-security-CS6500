import sys
import os
import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature


def create_keys(file_name, rsa_key_len):

	f = open(file_name, "r")

	for x in f:

		user = x.rstrip('\n')

		try:
			os.remove(user+"priv"+str(rsa_key_len)+".txt") 
			os.remove(user+"pub"+str(rsa_key_len)+".txt")

			print("Keys are getting generated for",user,"...")

		except FileNotFoundError:

			print("Keys are getting generated for",user,"...")
		
		private_key = rsa.generate_private_key(public_exponent=65537,key_size=rsa_key_len,backend=default_backend())
		
		private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
		public_key_bytes = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
		
		f1 = open(user+"priv"+str(rsa_key_len)+".txt", "wb")
		f1.write(private_key_bytes)

		f2 = open(user+"pub"+str(rsa_key_len)+".txt", "wb")
		f2.write(public_key_bytes) 

	f.close()
	f1.close()
	f2.close()

	return "Keys of length "+str(rsa_key_len)+" have been generated in the files of all the users."


def create_mail(SecType, Sender, Receiver, EmailInputFile, EmailOutputFile, DigestAlg, EncryAlg, RSAKeySize):

	try:
		f1 = open(EmailInputFile, "r")
		f2 = open(EmailOutputFile, "wb")

	except FileNotFoundError:

		print("File not found! Please check if you have entered the right input and output file names.")
		sys.exit(1)

	try:
		key_file1 = open(Receiver+"pub"+str(RSAKeySize)+".txt", "rb")
		key_file2 = open(Sender+"priv"+str(RSAKeySize)+".txt", "rb")

	except FileNotFoundError:

		print("File not found! Please check if you have entered the right values for RSA Key length, receiver and sender.")
		sys.exit(1)
	
	public_key = serialization.load_pem_public_key(key_file1.read(),backend=default_backend())
	private_key = serialization.load_pem_private_key(key_file2.read(),None, backend=default_backend())
			
	email_message = f1.read()
	
	if SecType == "CONF":

		ciphertext, key = encrypt_message(email_message, EncryAlg)

		encrypted_key = RSA_encrypt(public_key, key)

		f2.write(encrypted_key+b"\n")
		f2.write(ciphertext)

	elif SecType == "AUIN":

		email_message = bytes(email_message, 'utf-8')

		hash_string, encrypted_hash = hash_and_sign(email_message, private_key, DigestAlg)

		f2.write(encrypted_hash+b"\n")
		f2.write(email_message)

	elif SecType == "COAI":


		hash_string, encrypted_hash = hash_and_sign(bytes(email_message, 'utf-8'), private_key, DigestAlg)

		message = b"".join([(encrypted_hash), bytes(email_message, 'utf-8')])
		
		ciphertext, key = encrypt_message(message.decode("utf-8"), EncryAlg)

		encrypted_key = RSA_encrypt(public_key, key)
		
		f2.write(encrypted_key+b"\n")
		f2.write(ciphertext)

	f1.close()
	f2.close()

	return "Mail has been created in " + EmailOutputFile

def read_mail(SecType, Sender, Receiver, SecureInputFile, PlainTextOutputFile, DigestAlg, EncryAlg, RSAKeySize):

	try:
		f1 = open(SecureInputFile, "rb")
		f2 = open(PlainTextOutputFile, "wb")

	except FileNotFoundError:

		print("File not found! Please check if you have entered the right names for the input and output files.")
		sys.exit(1)
	
	try: 
		key_file1 = open(Receiver+"priv"+str(RSAKeySize)+".txt", "rb")
		key_file2 = open(Sender+"pub"+str(RSAKeySize)+".txt", "rb")

	except FileNotFoundError:

		print("File not found! Please check if you have entered the right values for RSA Key length, receiver and sender.")
		sys.exit(1)

	private_key = serialization.load_pem_private_key(key_file1.read(),None,backend=default_backend())
	public_key = serialization.load_pem_public_key(key_file2.read(),backend=default_backend())
	
	if SecType == "CONF":

		encrypted_key = f1.readline()
		encrypted_key = encrypted_key[0:len(encrypted_key)-1]
		encrypted_message = f1.readline()

		decrypted_key = RSA_decrypt(private_key, encrypted_key)
		
		f2.write(unpad(decrypt_message(decrypted_key, encrypted_message, EncryAlg)))

	elif SecType == "AUIN":

		encrypted_hash = f1.readline()
		encrypted_hash = encrypted_hash[0:len(encrypted_hash)-1]

		message = f1.readlines()
		message_concatenated = b""
		for i in range(len(message)):
			message_concatenated = b"".join([message_concatenated, message[i]])

		verify_match(message_concatenated, public_key, encrypted_hash, DigestAlg)

		return "The integrity of the sender has been validated."
		
	elif SecType == "COAI":

		encrypted_key = f1.readline()
		encrypted_key = encrypted_key[0:len(encrypted_key)-1]
		encrypted_message = f1.readline()
		hash_len = int((int(RSAKeySize)/1024) * 172)

		decrypted_key = RSA_decrypt(private_key, encrypted_key)

		temp = unpad(decrypt_message(decrypted_key, encrypted_message, EncryAlg))
		message = temp[hash_len:]
		encrypted_hash = temp[:hash_len]
		verify_match(message, public_key, encrypted_hash, DigestAlg)

		f2.write(message)
		SecureInputFile = SecureInputFile + " and the integrity of the sender has been validated."

	f1.close()
	f2.close()
	
	return "Mail has been read to " + PlainTextOutputFile +" from " + SecureInputFile


def RSA_encrypt(public_key, message):

	return base64.b64encode(public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)))


def RSA_decrypt(private_key, encrypted_message):

	return private_key.decrypt(base64.b64decode(encrypted_message),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

def pad(s, block_size):

	return s + (block_size - len(s) % block_size)*chr(block_size - len(s) % block_size)

def unpad(s):

	return s[:-ord(s[len(s)-1:])]

def encrypt_message(email_message, EncryAlg):

	if EncryAlg=='aes-256-cbc':

		session_key = os.urandom(32)
		iv = os.urandom(16)
		key = b"".join([session_key, iv])
		email_message = pad(email_message, 16)
		email_message = bytes(email_message, 'utf-8')
		cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
		encryptor = cipher.encryptor()
		ciphertext = base64.b64encode(encryptor.update(email_message) + encryptor.finalize())

	elif EncryAlg=='des-ede3-cbc':

		session_key = os.urandom(16)
		iv = os.urandom(8)
		key = b"".join([session_key, iv])
		email_message = pad(email_message, 8)
		email_message = bytes(email_message, 'utf-8')
		cipher = Cipher(algorithms.TripleDES(session_key), modes.CBC(iv))
		encryptor = cipher.encryptor()
		ciphertext = base64.b64encode(encryptor.update(email_message) + encryptor.finalize())

	return ciphertext, key


def decrypt_message(decrypted_key, encrypted_message, EncryAlg):

	if EncryAlg=='aes-256-cbc':

		session_key = decrypted_key[0:32]
		iv = decrypted_key[32:48]

		cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
		decryptor = cipher.decryptor()
		ciphertext = base64.b64decode(encrypted_message)

		return decryptor.update(ciphertext) + decryptor.finalize()

	if EncryAlg=='des-ede3-cbc':

		session_key = decrypted_key[0:16]
		iv = decrypted_key[16:24]

		cipher = Cipher(algorithms.TripleDES(session_key), modes.CBC(iv))
		decryptor = cipher.decryptor()
		ciphertext = base64.b64decode(encrypted_message)

		return decryptor.update(ciphertext) + decryptor.finalize()


def hash_and_sign(email_message, private_key, DigestAlg):

	if DigestAlg == "sha512":
		hash_string = hashlib.sha512(email_message).hexdigest()
		encrypted_hash = base64.b64encode(private_key.sign(bytes(hash_string.encode('ascii')),padding.PSS(mgf=padding.MGF1(hashes.SHA512()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA512()))
	else:
		hash_string = hashlib.sha3_512(email_message).hexdigest()
		encrypted_hash = base64.b64encode(private_key.sign(bytes(hash_string.encode('ascii')),padding.PSS(mgf=padding.MGF1(hashes.SHA3_512()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA3_512()))
		
	return hash_string, encrypted_hash


def verify_match(message, public_key, encrypted_hash, DigestAlg):

	if DigestAlg == "sha512":
		hash_string = hashlib.sha512(message).hexdigest()
		mgf = padding.MGF1(hashes.SHA512())
		algorithm = hashes.SHA512()
	else:
		hash_string = hashlib.sha3_512(message).hexdigest()
		mgf = padding.MGF1(hashes.SHA3_512())
		algorithm = hashes.SHA3_512()

	try:
		public_key.verify(base64.b64decode(encrypted_hash),bytes(hash_string.encode('ascii')),
			padding.PSS(
       		mgf = mgf,
        	salt_length=padding.PSS.MAX_LENGTH),
        	algorithm = algorithm)
		print('Validation successful!')
			
	except InvalidSignature:
		print('Oops! Invalid credentials.')
		sys.exit(1)


if sys.argv[1] == "CreateKeys":

	print(create_keys(sys.argv[2], int(sys.argv[3])))

elif sys.argv[1] == "CreateMail":

	print(create_mail(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8], sys.argv[9]))
	
elif sys.argv[1] == "ReadMail":

	print(read_mail(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8], sys.argv[9]))
