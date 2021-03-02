import codecs
import numpy as np
import random 

MOD = 256


def KSA(key):
    ''' Key Scheduling Algorithm 
    '''
    key_length = len(key)
    S = list(range(MOD))
    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % key_length]) % MOD
        S[i], S[j] = S[j], S[i] 

    return S


def PRGA(S):
    ''' Pseudo Random Generation Algorithm (from wikipedia):
    '''
    i = 0
    j = 0

    while True:
        i = (i + 1) % MOD
        j = (j + S[i]) % MOD

        S[i], S[j] = S[j], S[i] 
        K = S[(S[i] + S[j]) % MOD]
        
        
        yield K

def get_keystream(key):
    ''' Takes the encryption key to get the keystream using PRGA
        return object is a generator
    '''
    S = KSA(key)
    return PRGA(S)


def encrypt_logic(key, text):
    ''' :key -> encryption key used for encrypting, as hex string
        :text -> array of unicode values/ byte string to encrpyt/decrypt
    '''
    key = [ord(c) for c in key]
    keystream = get_keystream(key)
    
    res = []
    keystream_list = []
    for c in text:
        value = next(keystream)
        
        val = ("%02X" % (c ^ value))  # XOR and taking hex
        keystream_list.append("%02X" % value) 
        res.append(val)

    return ''.join(res),keystream_list


def encrypt(key, plaintext):
    ''' :key -> encryption key used for encrypting, as hex string
        :plaintext -> plaintext string to encrpyt
    '''
    plaintext = [ord(c) for c in plaintext]
    encrypted, keystream = encrypt_logic(key, plaintext)
    return encrypted, keystream


def decrypt(key, ciphertext):
    ''' :key -> encryption key used for encrypting, as hex string
        :ciphertext -> hex encoded ciphered text using RC4
    '''
    ciphertext = codecs.decode(ciphertext, 'hex_codec')
    res, random_key_stream = encrypt_logic(key, ciphertext)
    return codecs.decode(res, 'hex_codec').decode('utf-8'), random_key_stream

def rand_key(p): # Function to create the random binary string 
     
    key = "" 
    for i in range(p): 

        temp = str(random.randint(0, 1)) 
        key += temp 
          
    return(key) 

def main(key):
 
    
    plaintext = 'Plaintext' 
    ciphertext, random_key_stream1 = encrypt(key, plaintext)

    print('plaintext:', plaintext)
    print('ciphertext:', ciphertext) 
    print('random key stream:', random_key_stream1) # is this the output bit stream that we have to XOR??(it has 48, 49- corresponds to 0 and 1)

    decrypted, random_key_stream2 = decrypt(key, ciphertext)

    print('decrypted:', decrypted)
    print('random key stream:', random_key_stream2)

    if plaintext == decrypted:
        print('\nCongrats ! You made it.')
    else:
        print('Nope :(')
main('Key') # this is to test whether RC4 implementation is correct
