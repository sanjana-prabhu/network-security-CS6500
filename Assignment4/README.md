# Simple SSH Server and Client

## Run
```
$ python sshserver.py PortNumber
```
```
$ python sshclient.py localhost PortNumber username
```

The username-passphrase database is present in the sshserver.py file, from lines 161-165.

## Note:

- In command cp filename dir1 dir2, mv filename dir1 dir2 and cd dir, the directory names are not absolute, i.e., assume that you are in the current working directory and then enter the cp, mv and cd commands. This is done so as to adjust for the limited length possible for the messages sent via TCP from the client to the server. 

- Before every new client logs in, the previous working directory(the directory that contains the codes, ServerKeys and UserCredentials folders) is restored.
