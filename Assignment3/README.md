****************************************************************************************************************************************
************************************************** ASSIGNMENT 3 Network Security *******************************************************
****************************************************************************************************************************************


This assignment is about facilitating client to client communication in an encrypted manner using a key distribution centre(KDC).

In order to test the KDC-client system, follow the steps given below:

1. Create three text files, output.txt - to store the diagnostic outputs describing the KDC's activities, in.txt - to store the message to be sent from sender to receiver and pwd.txt - for the KDC to store the password details of the clients, in the same directory as the Python scripts.

2. To start the KDC and to make it listen on a given port number, enter the following command on the terminal:
   
   python kdc.py -p KDCPortNumber -o output.txt -f pwd.txt 

3. To register the sender client and make it send the message(stored in in.txt), enter the following command on the terminal:

   python client.py -n sendername -m S -o receivername -i in.txt -a KDCIP -p KDCPortNumber

4. To register the receiver client and make it listen to the messages(on its port), enter the following command on the terminal:

   python client.py -n bob -m R -s outenc.txt -o outfile.txt -a KDCIP -p KDCPortNumber

   Note that the encrypted message received by the receiver will be stored in outenc.txt and the decrypted version of the same will be stored in outfile.txt.


The following is a sample session for testing out the code:

Terminal Window 1: $ python kdc.py -p 12345 -o output.txt -f pwd.txt

Terminal Window 2: $ python client.py -n alice -m S -o bob -i in.txt -a 127.0.0.1 -p 12345

Terminal Window 3: $ python client.py -n bob -m R -s outenc.txt -o outfile.txt -a 127.0.0.1 -p 12345

After these three steps, in about 5-10 seconds, the message is sent via TCP sockets from the sender to the receiver and the commands in Terminal Windows 2 and 3 finish executing. Now, press Ctrl+C in Terminal Window 1 in order to stop the kdc.py execution. This will generate the log of the entire session in the output.txt file. If you wish to send another message between the same or different clients, you may do so(before Ctrl+C). These activities will also get updated in the log.


Note : 

1) Steps 3 and 4 can be performed in any order(after Steps 1 and 2), but, if you perform Step 3 first, just ensure that Step 4 is executed within 5 seconds of entering the previous command so as to avoid issues due to the finite sleep time of the clients and the fact that registration, key request and sending the message is done in the same script. However, for convenience, you can do this: Perform Steps 1, 2 and 4 in that order. After this, you can perform Step 3 at your own convenience. 

2) There is an upper limit on the file size for input.txt(660 bytes), due to the fact that socket.recv(1024) is done in the scripts to receive the packets sent over the TCP sockets. This restricts the length of the message and can be changed by increasing the argument of socket.recv().

3) The IP address used for communication is 127.0.0.1 and is hard-coded in the socket.bind() commands for the sender and receiver clients.

4) If you run into this error : 
File "kdc.py", line 120, in enable_KDC
    s.bind(("localhost", int(port))) 
OSError: [Errno 98] Address already in use

a) Use this command to fix it : kill -9 $(ps -A | grep python | awk '{print $1}')
b) If that does not work out, wait for sometime OR change the port number of the KDC(in all three commands).

5) Also, please ensure that the port number(KDC port number) is a 5 digit number between 10000 to 65535. This has been taken care of for the clients' TCP ports.

6) Note that the output.txt and outenc.txt files will get generated only after you exit the kdc.py execution using Ctrl+C.
