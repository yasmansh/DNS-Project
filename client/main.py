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

    with open(os.path.join('..', 'server', 'PU_server.pem'), "rb") as f:
        data = f.read()
        server_public_key = rsa.PublicKey.load_pkcs1(data)


    with open(f'PU_client.pem', "rb") as f:
        data = f.read()
        public_key = rsa.PublicKey.load_pkcs1(data)
    with open(f'PR_client.pem', "rb") as f:
        data = f.read()
        private_key = rsa.PrivateKey.load_pkcs1(data)

    message = f"{public_key}"
    client.send(encrypt_and_sign(message, private_key, server_public_key))
    while True:
        # try:
        cipher = client.recv(4196)
        ok, message_split = check_sign_and_timestamp(client, cipher, private_key, server_public_key)
        if not ok:
            continue
        message_type = message_split[0]
        if message_type == 'M':
            m = message_split[1]
            print(m, end=' ')
            if m.strip() == 'Registration successful':
                create_db(username)
            elif m.strip() == 'Login successful':
                db = sqlite3.connect(f'../client_db/{username}.db')
                db.execute("PRAGMA foreign_keys = ON")
        elif message_type == 'D':  # D||get||username||id      D||set||username||id||ticket     D||edit||content
            demand_type = message_split[1]
            if demand_type == 'get':
                db_username = message_split[2]
                flag_db = sqlite3.connect(f"../client_db/{db_username}.db")
                flag_db.execute("PRAGMA foreign_keys = ON")
                file_id = int(message_split[3])
                key = select_from_file_keys(flag_db, file_id)
                if key is None:
                    message = f"None"
                else:
                    file_id = key['file_id']
                    file_ticket = key['ticket']
                    message = f"{file_ticket}"
                send_message(client, message, server_public_key, private_key)
            elif demand_type == 'set':
                db_username = message_split[2]
                flag_db = sqlite3.connect(f"../client_db/{db_username}.db")
                flag_db.execute("PRAGMA foreign_keys = ON")
                file_id = int(message_split[3])
                token = message_split[4]
                key = select_from_file_keys(flag_db, file_id)
                if key is None:
                    insert_into_file_keys(flag_db, file_id, token)
                else:
                    update_token(flag_db, file_id, token)
            elif demand_type == 'edit':
                cipher = eval(message_split[3])
                file_id = int(message_split[2])
                file_key = get_file_key(db, file_id)
                plaintext = decrypt_cipher(cipher, file_key['private_key'])
                new_plaintext = click.edit(plaintext)
                new_cipher = encrypt_message(new_plaintext, file_key['public_key'])
                message = f"{new_cipher}"
                send_message(client, message, server_public_key, private_key)
            elif demand_type == 'cat':
                file_id = int(message_split[2])
                cipher = eval(message_split[3])
                file_key = get_file_key(db, file_id)
                plaintext = decrypt_cipher(cipher, file_key['private_key'])
                print(plaintext)
            elif demand_type == 'touch':
                file_id = int(message_split[2])
                pu, pr = rsa.newkeys(512)
                token = message_split[3]
                query = f"INSERT INTO file_keys VALUES ({file_id}, '{pu}', '{pr}', '{token}')"
                db.execute(query)
                db.commit()
                file = get_file_key(db, file_id)
                file_public_key = file['public_key']
                message = encrypt_message(' ', file_public_key)
                cipher = encrypt_and_sign(f"{message}", private_key, server_public_key)
                client.send(cipher)
            elif demand_type == 'get_key':  # D||get_key||file_id||dest_user_public_key
                file_id = int(message_split[2])
                file = get_file_key(db, file_id)
                file_id = file["file_id"]
                dest_user_public_key = eval(message_split[3])
                keys = f"{file['public_key']}||{file['private_key']}"
                print('cccccccccccc')
                print(file['public_key'])
                print(file['private_key'])
                print('cccccccccccc')
                message = str(encrypt_message(keys, dest_user_public_key))
                cipher = encrypt_and_sign(message, private_key, server_public_key)
                client.send(cipher)
            elif demand_type == 'set_key':  # D||set_key||username||file_id||keys
                print('xxxx')
                dest_username = message_split[2]
                file_id = int(message_split[3])
                keys = eval(message_split[4])
                keys_plain = decrypt_cipher(keys, private_key)
                keys_plain_split = keys_plain.split('||')
                pu = keys_plain_split[0]
                pr = keys_plain_split[1]
                flag_db = sqlite3.connect(f'../client_db/{dest_username}.db')
                flag_db.execute("PRAGMA foreign_keys = ON")
                update_file_keys(flag_db, file_id, pu, pr)
        elif message_type == 'I':
            m = message_split[1]
            print(m, end=' ')
            cmd = input()
            cmd_split = cmd.split(' ')
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
            elif cmd_type == 'mkdir' or cmd_type == 'cd' or cmd_type == 'edit' or cmd_type == 'cat':
                path = cmd_split[1]
                message = f"{cmd_type}||{path}"
                cipher = encrypt_and_sign(message, private_key, server_public_key)
                client.send(cipher)
            elif cmd_type == 'touch':
                path = cmd_split[1]
                content = ' '
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
            elif cmd_type == 'share':
                path = cmd_split[1]
                dest_username = cmd_split[2]
                access_level = cmd_split[3][1:]
                message = f"{cmd_type}||{path}||{dest_username}||{access_level}"
                cipher = encrypt_and_sign(message, private_key, server_public_key)
                client.send(cipher)
            elif cmd_type == 'revoke':
                path = cmd_split[1]
                if len(cmd_split) == 2:
                    dest_username = '-'
                else:
                    dest_username = cmd_split[2]
                message = f"{cmd_type}||{path}||{dest_username}"
                cipher = encrypt_and_sign(message, private_key, server_public_key)
                client.send(cipher)
            else:
                message = f"{cmd_type}"
                cipher = encrypt_and_sign(message, private_key, server_public_key)
                client.send(cipher)
            # else send message to server
    client.close()
