#!/bin/sh
echo "Enter the key size you want to use for RSA"
read key
python3 Assignment2.py CreateKeys Usernames.txt $key
echo "Testing CONF(aes-256-cbc), enter the usernames of the sender"
read user1
echo "Enter the username of the receiver"
read user2
python3 Assignment2.py CreateMail CONF $user1 $user2 Mail-sample.txt Mail-out.txt sha512 aes-256-cbc $key
python3 Assignment2.py ReadMail CONF $user1 $user2 Mail-out.txt Mail-decrypt.txt sha512 aes-256-cbc $key
diff Mail-sample.txt Mail-decrypt.txt > result.txt
echo "Storing the difference between Mail-sample.txt and Mail-decrypt.txt in result.txt"
echo "Displaying the result.txt file"
cat result.txt
echo "Testing CONF(des-ede3-cbc), enter the usernames of the sender"
read user1
echo "Enter the username of the receiver"
read user2
python3 Assignment2.py CreateMail CONF $user1 $user2 Mail-sample.txt Mail-out.txt sha512 des-ede3-cbc $key
python3 Assignment2.py ReadMail CONF $user1 $user2 Mail-out.txt Mail-decrypt.txt sha512 des-ede3-cbc $key
diff Mail-sample.txt Mail-decrypt.txt > result.txt
echo "Storing the difference between Mail-sample.txt and Mail-decrypt.txt in result.txt"
echo "Displaying the result.txt file"
cat result.txt
echo "Testing AUIN(sha512), enter the usernames of the sender"
read user1
echo "Enter the username of the receiver"
read user2
python3 Assignment2.py CreateMail AUIN $user1 $user2 Mail-sample.txt Mail-out.txt sha512 aes-256-cbc $key
python3 Assignment2.py ReadMail AUIN $user1 $user2 Mail-out.txt Mail-decrypt.txt sha512 aes-256-cbc $key
echo "Testing AUIN(sha-3-512), enter the usernames of the sender"
read user1
echo "Enter the username of the receiver"
read user2
python3 Assignment2.py CreateMail AUIN $user1 $user2 Mail-sample.txt Mail-out.txt sha-3-512 aes-256-cbc $key
python3 Assignment2.py ReadMail AUIN $user1 $user2 Mail-out.txt Mail-decrypt.txt sha-3-512 aes-256-cbc $key
echo "Testing COAI(aes-256-cbc, sha512), enter the usernames of the sender"
read user1
echo "Enter the username of the receiver"
read user2
python3 Assignment2.py CreateMail COAI $user1 $user2 Mail-sample.txt Mail-out.txt sha512 aes-256-cbc $key
python3 Assignment2.py ReadMail COAI $user1 $user2 Mail-out.txt Mail-decrypt.txt sha512 aes-256-cbc $key
diff Mail-sample.txt Mail-decrypt.txt > result.txt
echo "Storing the difference between Mail-sample.txt and Mail-decrypt.txt in result.txt"
echo "Displaying the result.txt file"
cat result.txt
echo "Testing COAI(des-ede3-cbc, sha512), enter the usernames of the sender"
read user1
echo "Enter the username of the receiver"
read user2
python3 Assignment2.py CreateMail COAI $user1 $user2 Mail-sample.txt Mail-out.txt sha512 des-ede3-cbc $key
python3 Assignment2.py ReadMail COAI $user1 $user2 Mail-out.txt Mail-decrypt.txt sha512 des-ede3-cbc $key
diff Mail-sample.txt Mail-decrypt.txt > result.txt
echo "Storing the difference between Mail-sample.txt and Mail-decrypt.txt in result.txt"
echo "Displaying the result.txt file"
cat result.txt
echo "Testing COAI(aes-256-cbc, sha-3-512), enter the usernames of the sender"
read user1
echo "Enter the username of the receiver"
read user2
python3 Assignment2.py CreateMail COAI $user1 $user2 Mail-sample.txt Mail-out.txt sha-3-512 aes-256-cbc $key
python3 Assignment2.py ReadMail COAI $user1 $user2 Mail-out.txt Mail-decrypt.txt sha-3-512 aes-256-cbc $key
diff Mail-sample.txt Mail-decrypt.txt > result.txt
echo "Storing the difference between Mail-sample.txt and Mail-decrypt.txt in result.txt"
echo "Displaying the result.txt file"
cat result.txt
echo "Testing COAI(des-ede3-cbc, sha-3-512), enter the usernames of the sender"
read user1
echo "Enter the username of the receiver"
read user2
python3 Assignment2.py CreateMail COAI $user1 $user2 Mail-sample.txt Mail-out.txt sha-3-512 des-ede3-cbc $key
python3 Assignment2.py ReadMail COAI $user1 $user2 Mail-out.txt Mail-decrypt.txt sha-3-512 des-ede3-cbc $key
diff Mail-sample.txt Mail-decrypt.txt > result.txt
echo "Storing the difference between Mail-sample.txt and Mail-decrypt.txt in result.txt"
echo "Displaying the result.txt file"
cat result.txt

