import base64
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