All the scripts are in Python.
Dependencies : cryptography

The script file test.sh tests out all the 3 security services for various Digest algorithms and encryption algorithms and can handle RSA key sizes of 1024, 2048.

Note : The sample mail and Usernames.txt files are present in the folder. Please modify/make use of these, but do not modify the names of these files. All types of mails are handled - multiple and single line mails, mails will length unequal to the block sizes of the encryption algorithms. For the usernames, please enter the usernames with a nextline character after each username, except the last one.

For every security service, the mail is stored in Mail-sample.txt, the output of CreateMail is stored in Mail-out.txt and the read mail is stored in Mail-decrypt.txt.

Run the script file using :

bash test.sh

To generate RSA keys for usernames stored in Usernames.txt use the following command:

python3 Assignment2.py CreateKeys Usernames.txt RSAKeySize

To test out any individual security mechanism, use the commands :

python3 Assignment2.py CreateMail SecType Sender Receiver EmailInputFile EmailOutputFile DigestAlg EncryAlg RSAKeySize
python3 Assignment2.py ReadMail SecType Sender Receiver SecureInputFile PlainTextOutputFile DigestAlg EncryAlg RSAKeySize

Error cases :

- cannot handle RSAKeySizes other than 1024, 2048.
