import hashlib
import socket
import sqlite3
import rsa
import os
from utils import encrypt_and_sign, check_sign_and_timestamp, send_message, decrypt_cipher, encrypt_message
from db_utils import *
import click


if __name__ == '__main__':
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

    message = f"{public_key}"
    client.send(encrypt_and_sign(message, private_key, server_public_key))
    while True:
        # try:
        cipher = client.recv(2048)
        ok, message_split = check_sign_and_timestamp(client, cipher, private_key, server_public_key)
        if not ok:
            continue
        message_type = message_split[0]
        if message_type == 'M':
            m = message_split[1]
            print(m)
        elif message_type == 'D':  # D||get||id      D||set||id||ticket     D||edit||content
            print(message_split)
            demand_type = message_split[1]
            if demand_type == 'get':
                file_id = int(message_split[2])
                key = select_from_file_keys(db, file_id)
                if key is None:
                    message = f"None"
                else:
                    file_id = key['file_id']
                    file_ticket = key['ticket']
                    message = f"{file_ticket}"
                send_message(client, message, server_public_key, private_key)
            elif demand_type == 'set':
                file_id = int(message_split[2])
                token = message_split[3]
                file_id = int(message_split[2])
                key = select_from_file_keys(db, file_id)
                if key is None:
                    insert_into_file_keys(db, file_id, token)
                else:
                    update_token(db, file_id, token)
            elif demand_type == 'edit':
                cipher = eval(message_split[2])
                plaintext = decrypt_cipher(cipher, private_key)
                new_plaintext = click.edit(plaintext)
                new_cipher = encrypt_message(new_plaintext, public_key)
                message = f"{new_cipher}"
                send_message(client, message, server_public_key, private_key)
            elif demand_type == 'cat':
                cipher = eval(message_split[2])
                plaintext = decrypt_cipher(cipher, private_key)
                print(plaintext)
        elif message_type == 'I':
            m = message_split[1]
            print(m)
            cmd = input('Enter Input: ')
            cmd_split = cmd.split('||')
            cmd_type = cmd_split[0]
            if cmd_type == '1':
                first_name = cmd_split[1]
                last_name = cmd_split[2]
                username = cmd_split[3]
                password = cmd_split[4]
                hash_password = hashlib.sha256(str.encode(password)).hexdigest()
                message = f"1||{first_name}||{last_name}||{username}||{hash_password}"
                cipher = encrypt_and_sign(message, private_key, server_public_key)
                client.send(cipher)
            elif cmd_type == '2':
                username = cmd_split[1]
                password = cmd_split[2]
                hash_password = hashlib.sha256(str.encode(password)).hexdigest()
                message = f'2||{username}||{hash_password}'
                cipher = encrypt_and_sign(message, private_key, server_public_key)
                client.send(cipher)
            elif cmd_type == '3':
                message = f"3"
                cipher = encrypt_and_sign(message, private_key, server_public_key)
                client.send(cipher)
            else:
                cmd_split = cmd.split(' ')
                cmd_type = cmd_split[0]
                if cmd_type == 'mkdir' or cmd_type == 'cd' or cmd_type == 'edit' or cmd_type == 'cat':
                    path = cmd_split[1]
                    message = f"{cmd_type}||{path}"
                    cipher = encrypt_and_sign(message, private_key, server_public_key)
                    client.send(cipher)
                elif cmd_type == 'touch':
                    path = cmd_split[1]
                    content = encrypt_message(' ', public_key)
                    print('xxx', content)
                    message = f"{cmd_type}||{path}||{content}"
                    cipher = encrypt_and_sign(message, private_key, server_public_key)
                    client.send(cipher)
                elif cmd_type == 'ls':
                    if len(cmd_split) == 1 or cmd_split[1] == '':
                        path = '.'
                    else:
                        path = cmd_split[1]
                    message = f"{cmd_type}||{path}"
                    cipher = encrypt_and_sign(message, private_key, server_public_key)
                    client.send(cipher)
                elif cmd_type == 'rm':
                    if cmd_split[1] == '-r':
                        path = cmd_split[2]
                        message = f"{cmd_type}||folder||{path}"
                    else:
                        path = cmd_split[1]
                        message = f"{cmd_type}||file||{path}"
                    cipher = encrypt_and_sign(message, private_key, server_public_key)
                    client.send(cipher)
                elif cmd_type == 'mv':
                    if cmd_split[1] == '-r':
                        src_path = cmd_split[2]
                        dest_path = cmd_split[3]
                        message = f"{cmd_type}||folder||{src_path}||{dest_path}"
                    else:
                        src_path = cmd_split[1]
                        dest_path = cmd_split[2]
                        message = f"{cmd_type}||file||{src_path}||{dest_path}"
                    cipher = encrypt_and_sign(message, private_key, server_public_key)
                    client.send(cipher)
                # else send message to server
    client.close()
