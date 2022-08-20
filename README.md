# DNS-Project

It is a Secure File System that is a file server that allows users to securely store and share their data on an untrusted server. We use access control for each user and users can set another user's permission for their shared files. Also, users have their own space and have a command line like Terminal in Linux.

Data and files are encrypted by the server's private key and the client's public key and a timestamp each time.
Each time a client requests a file, filename, or directory name, the server decrypts the data before sending it to the RSA encoder for communication.
