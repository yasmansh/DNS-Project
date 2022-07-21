import hashlib
import socket
import sqlite3
import rsa
import os
from server.utils import encrypt_and_sign, check_sign_and_timestamp


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
        elif message_type == 'D':  # D||get||file/dir||id      D||set||file/dir||id||ticket
            get_or_set = message_split[1]
            m = message_split[2]
            file_id = message_split[3]
            if get_or_set == 'get':
                if m == 'file':
                    file_id = message_split[3]
                    query = f"""SELECT * FROM file_keys WHERE id={file_id}"""
                    response = db.execute(query).fetchone()
                    if response is None:
                        ticket = 'none'
                    else:
                        ticket = response[4]
                message = f"{ticket}"
                cipher = encrypt_and_sign(message, private_key, server_public_key)
                client.send(cipher)
            elif get_or_set == 'set':
                ticket = message_split[4]
                if m == 'file':
                    file_id = message_split[3]
                    query = f"SELECT * FROM file_keys WHERE id={file_id}"
                    response = db.execute(query).fetchone()
                    if response is None:
                        query = f"""INSERT INTO file_keys
                        VALUES ({file_id}, "{ticket}")"""
                        db.execute(query)
                        db.commit()
                    else:
                        query = f"""UPDATE file_keys
                        SET ticket={ticket}
                        WHERE id={file_id}"""
                        db.execute(query)
                        db.commit()
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
                if cmd_type == 'mkdir' or cmd_type == 'touch' or cmd_type == 'cd':
                    path = cmd_split[1]
                    message = f"{cmd_type}||{path}"
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
                # else send message to server
    client.close()
