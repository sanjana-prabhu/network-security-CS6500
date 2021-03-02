import codecs
import numpy as np
import random 
import matplotlib.pyplot as plt 

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
    ''' Pseudo Random Generation Algorithm:
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
        keystream_list.append("%02X" %value) # keystream
        res.append(val)
    return ''.join(res),keystream_list


def encrypt(key, plaintext):
    ''' :key -> encryption key used for encrypting, as hex string
        :plaintext -> plaintext string to encrpyt
    '''
    plaintext = [ord(c) for c in plaintext]
    return encrypt_logic(key, plaintext)


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

def main(key): # Function to check how RC4 works
     
    plaintext = 'plaintext' 
    ciphertext, random_key_stream1 = encrypt(key, plaintext)

    print('plaintext:', plaintext)
    print('ciphertext:', ciphertext) 
    print('random key stream:', random_key_stream1) 

    decrypted, random_key_stream2 = decrypt(key, ciphertext)

    print('decrypted:', decrypted)
    print('random key stream:', random_key_stream2)

    if plaintext == decrypted:
        print('\nCongrats ! You made it.')
    else:
        print('Nope :(')

#main("111") # to test whether RC4 implementation is correct

def randomness(output_len, counter_len, xored_output): # Function to find the randomness in a bitstream

    counter = np.zeros(counter_len)

    for i in range(output_len-7):

        number = int(bin2dec(xored_output[i:i+8]))
        counter[number] = counter[number]+1


    std_dev = np.std(counter)
    #print(counter) # Uncomment this to check how the counter looks at any interval
    
    return (std_dev*counter_len)/output_len

def xor_func(random_key_stream1, random_key_stream2): # Function to XOR two bitstreams

    xored_output = np.zeros(8*len(random_key_stream1))
    binary_array1 = np.zeros(8)
    binary_array2 = np.zeros(8)

    for i in range(len(random_key_stream1)):

        binary_array1 = hex2bin(random_key_stream1[i])
        binary_array2 = hex2bin(random_key_stream2[i])
        xored_output[8*i:8*i+8] = binary_array1 + binary_array2

    xored_output[xored_output==2] = 0

    return xored_output

def hex2bin(hnum): # Function to convert a hexadecimal number to a array of 8 bits

    hnum = int(hnum, 16)
    bnum = bin(hnum)

    binary_array = np.zeros(8)
    for i in range(len(bnum)-2):
        binary_array[7-i] = int(bnum[len(bnum)-i-1])
    
    return binary_array

def bin2dec(bin_array): # Function to convert a 8 bit binary to a decimal number

    number = 0
    for i in range(len(bin_array)):

        number = number + bin_array[7-i]*(2**i)
    
    return number

## Main code starts here

output_len_array = [2,4,8,32,128,1024]

toggle_bits = 32

iterations = 100

standard_dev = np.zeros([len(output_len_array), toggle_bits])

for i in range(len(output_len_array)):

   for j in range(toggle_bits):

    sum_stddev = 0
    key1 = rand_key(2048)
    plaintext = rand_key(output_len_array[i])
    ciphertext1, random_key_stream1 = encrypt(key1, plaintext)
    key1_list = []
    key1_list[:0] = key1
    key2_list = key1_list

    for k in range(iterations):
            
        toggle_index = random.sample(range(2048), j+1)

        for t in range(len(toggle_index)):
                
            key2_list[toggle_index[t]] = abs(int(key2_list[toggle_index[t]])-1)

        key2 = "".join(str(e) for e in key2_list)

        ciphertext2, random_key_stream2 = encrypt(key2, plaintext)

        xored_output = xor_func(random_key_stream1, random_key_stream2)
        
        sum_stddev = sum_stddev + randomness(8*output_len_array[i], 256, xored_output)

    standard_dev[i,j] = sum_stddev/iterations

    #print(i,j)

#print(standard_dev)

## Plots
X = np.linspace(1, 32, 32)

plt.plot(X, standard_dev[0,:])
plt.xlabel('Number of bits toggled') 
plt.ylabel('Randomness') 
plt.title('Randomness vs toggle_bits curve for output length of 2 bytes')  
plt.show() 

plt.plot(X, standard_dev[1,:])
plt.xlabel('Number of bits toggled') 
plt.ylabel('Randomness') 
plt.title('Randomness vs toggle_bits curve for output length of 4 bytes')  
plt.show() 

plt.plot(X, standard_dev[2,:])
plt.xlabel('Number of bits toggled') 
plt.ylabel('Randomness') 
plt.title('Randomness vs toggle_bits curve for output length of 8 bytes')  
plt.show() 

plt.plot(X, standard_dev[3,:])
plt.xlabel('Number of bits toggled') 
plt.ylabel('Randomness') 
plt.title('Randomness vs toggle_bits curve for output length of 32 bytes')  
plt.show() 

plt.plot(X, standard_dev[4,:])
plt.xlabel('Number of bits toggled') 
plt.ylabel('Randomness') 
plt.title('Randomness vs toggle_bits curve for output length of 128 bytes')  
plt.show() 

plt.plot(X, standard_dev[5,:])
plt.xlabel('Number of bits toggled') 
plt.ylabel('Randomness') 
plt.title('Randomness vs toggle_bits curve for output length of 1024 bytes')  
plt.show() 