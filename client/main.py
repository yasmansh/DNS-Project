import hashlib
import socket
import datetime
import sqlite3

import rsa
import os
from server.utils import get_timestamp, encrypt_message, check_freshness, decrypt_cipher

host = ""
port = 0
with open("configuration_ip_port", "r") as f:
    host = f.readline().strip()
    port = int(f.readline().strip())

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))
db = sqlite3.connect('client.db')

with open(os.path.join('..', 'server', 'PU_server.pem'), "rb") as f:
    data = f.read()
    server_public_key = rsa.PublicKey.load_pkcs1(data)

with open('PU_client.pem', "rb") as f:
    data = f.read()
    public_key = rsa.PublicKey.load_pkcs1(data)

with open('PR_client.pem', "rb") as f:
    data = f.read()
    private_key = rsa.PrivateKey.load_pkcs1(data)

while True:
    # try:
    response = client.recv(2048).decode()
    if response[-1] == '|':
        print(response[:-1])
        continue
    print(response)
    command = input()
    cmd_split = command.split('$')
    cmd_type = cmd_split[0]
    if cmd_type == '1':
        first_name = cmd_split[1]
        last_name = cmd_split[2]
        username = cmd_split[3]
        password = cmd_split[4]
        hash_password = hashlib.sha256(str.encode(password)).hexdigest()
        sign = rsa.sign(str(public_key).encode(), private_key, 'SHA-256')
        timestamp = get_timestamp()
        message = f'1${first_name}${last_name}${username}${hash_password}${public_key}${sign}${timestamp}'
        cipher = encrypt_message(message, server_public_key)
        client.send(cipher)
    elif cmd_type == '2':
        username = cmd_split[1]
        password = cmd_split[2]
        hash_password = hashlib.sha256(str.encode(password)).hexdigest()
        timestamp = get_timestamp()
        message = f'2${username}${hash_password}${timestamp}'
        cipher = encrypt_message(message, server_public_key)
        client.send(cipher)
    elif cmd_type == '3':
        timestamp = get_timestamp()
        message = f"3${timestamp}"
        cipher = encrypt_message(message, server_public_key)
        client.send(cipher)
    else:
        cmd_split = command.split(' ')
        cmd_type = cmd_split[0]
        if cmd_type == 'mkdir':
            timestamp = get_timestamp()
            path = cmd_split[1]
            message = f"mkdir${path}${hash_password}${timestamp}"
            cipher = encrypt_message(message, server_public_key)
            client.send(cipher)
            while True:
                message = client.recv(2048).decode()
                print(message, type(message))
                message = decrypt_cipher(message, private_key)
                message_split = message.split('$')
                if check_freshness(message_split[-1]):
                    if message[0] == 'Completed':
                        break
                    elif message[0] == 'Send Folder Ticket':
                        query = f"SELECT * FROM dir_keys WHERE id={message[1]}"
                        response = db.execute(query)
                        response = response.fetchone()
                        ticket = response[2]
                        timestamp = get_timestamp()
                        message = str.encode(f"{ticket}${timestamp}")
                        cipher = encrypt_message(message, server_public_key)
                        client.send(cipher)
# except Exception as e:
    #     print("Error")
    #     break
client.close()
