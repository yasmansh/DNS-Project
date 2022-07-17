import socket
import threading
import hashlib
import rsa
from rsa import PublicKey
import datetime
import os
import shutil
import click
import sqlite3
import random
import string
from time import sleep

import client.main
from utils import get_timestamp, random_string, decrypt_cipher, encrypt_and_sign, \
    check_sign_and_timestamp, encrypt_message, insert_query, gen_nonce, write_meta


def hash_file(filename):
    h = hashlib.sha256()
    with open(filename, 'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h.update(chunk)

    return h.hexdigest()


def get_folder_metadata(path):
    f = open(os.path.join(path, '.meta'), 'rb')
    cipher_data = f.read()
    f.close()
    data = decrypt_cipher(cipher_data, private_key)
    data_split = data.split("\n")
    return data_split


def check_meta(path, timestamp):
    data_split = get_folder_metadata(path)
    list_dir = os.listdir(path)
    if len(list_dir) != data_split[1] or timestamp != data_split[2]:
        return False
    for row in data_split[3:]:
        name_hash = row.split('||')
        file_name = name_hash[0]
        file_hash = name_hash[1]
        file_path = os.path.join(path, file_name)
        if not os.path.exists(file_path) or hash_file(file_path) != file_hash:
            return False
    return True


def get_full_path(db, folder_id):
    res = ''
    while folder_id != 1:
        query = f"SELECT * FROM dirs WHERE id={folder_id}"
        folder = db.execute(query).fetchone()
        folder_name = folder[1]
        folder_parent = folder[2]
        res = os.path.join(folder_name, res)
        folder_id = folder_parent
    return res


def make_path(path, username, db, client, user_public_key, user_base_dir_id):
    path_split = path.split(os.path.sep)
    for new_folder in path_split:
        metadata = get_folder_metadata(os.getcwd())
        folder_id = eval(metadata[0])
        query = f'SELECT * FROM dirs WHERE id={folder_id}'
        folder_data = db.execute(query).fetchone()
        folder_base = folder_data[6]
        if new_folder == '.':
            continue
        elif new_folder == '..':
            if folder_base != 1:
                os.chdir(os.path.join(os.getcwd(), '..'))
            continue
        parent_id = folder_id if folder_id != 1 else user_base_dir_id
        query = f'SELECT * FROM dirs WHERE name="{new_folder}" and parent_id={parent_id}'
        new_folder_data = db.execute(query).fetchone()
        if new_folder_data is not None:
            list_dir = os.listdir()
            print(list_dir)
            for cipher in list_dir:
                if os.path.isdir(cipher):
                    real_name = rsa.decrypt(bytes.fromhex(cipher), private_key).decode()
                    if real_name == new_folder:
                        new_folder_name = cipher
                        break
            os.chdir(new_folder_name)
            data_split = get_folder_metadata(os.getcwd())
            dir_id = data_split[0]
            query = f"""SELECT * FROM dirs_access
            WHERE dir_id={dir_id} and username="{username}" """
            access = db.execute(query).fetchone()
            rw = access[3]
            if rw == 0:
                message = f"M||You don't have required access.\n|"
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                return False
            message = f"D||get||dir||{dir_id}"
            cipher = encrypt_and_sign(message, private_key, user_public_key)
            client.send(cipher)
            cipher = client.recv(2048)
            ok, message_split = check_sign_and_timestamp(cipher, private_key, user_public_key, client)
            if not ok:
                break
            ticket = message_split[0]
            query = f"""SELECT * FROM dirs
            WHERE id={dir_id}"""
            response = db.execute(query).fetchone()
            nonce = response[4]
            if ticket != nonce:
                message = "M||You don't have required access.\n|"
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                return False
        else:
            new_folder_name = rsa.encrypt(new_folder.encode(), public_key).hex()
            read_token = gen_nonce()
            write_token = gen_nonce()
            timestamp = get_timestamp()
            query = f"""INSERT INTO dirs (name, parent_id, read_token, write_token, timestamp, base)
                        VALUES ("{new_folder}", {parent_id}, "{read_token}", "{write_token}",
                         {timestamp}, false)"""
            insert_query(db, query)
            query = f"""SELECT * FROM dirs
                    WHERE name="{new_folder}" and parent_id={parent_id}
                    """
            response = db.execute(query)
            folder = response.fetchone()
            folder_id = folder[0]
            query = f"""INSERT INTO dirs_access (dir_id, username, owner, rw)
                        VALUES ({folder_id}, "{username}", true, true)"""
            insert_query(db, query)
            message = f"D||set||dir||{folder_id}||{write_token}"
            cipher = encrypt_and_sign(message, private_key, user_public_key)
            client.send(cipher)
            os.mkdir(new_folder_name)
            os.chdir(new_folder_name)
            content = f"""{folder_id}
{timestamp}
1"""
            write_meta(os.getcwd(), content, public_key)
    return True


def secure_file_system(client, username, user_public_key, db):
    query = f'SELECT * FROM accounts WHERE username="{username}"'
    user = db.execute(query).fetchone()
    base_dir_id = user[4]
    query = f"SELECT * FROM dirs WHERE id={base_dir_id}"
    base_dir = db.execute(query).fetchone()
    current_dir_id = base_dir_id
    while True:
        message = f"I||{get_full_path(db, current_dir_id)}>"
        cipher = encrypt_and_sign(message, private_key, user_public_key)
        client.send(cipher)
        cipher = client.recv(2048)
        ok, cmd_split = check_sign_and_timestamp(cipher, private_key, user_public_key, client)
        if not ok:
            continue
        cmd_type = cmd_split[0]
        if cmd_type == 'mkdir':  # mkdir$path$password$timestamp
            path = cmd_split[1]
            ra_cwd = os.getcwd()
            res = make_path(path, username, db, client, user_public_key, base_dir_id)
            os.chdir(ra_cwd)
            if res:
                message = 'M||Folder Created Successfully'
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                sleep(1)

        # elif command.startswith('touch'):
        # elif command.startswith('cd'):
        #     path = os.path.join(base_path, command.split()[1])
        #     try:
        #         os.chdir(path)
        #         base_path = os.getcwd()
        #     except:
        #         client.send(str.encode('error|'))
        #         pass
        # elif command == 'ls':
        #     client.send(str.encode(str(os.listdir(base_path)) + '|'))
        # elif command.startswith('ls'):
        #     path = os.path.join(base_path, command.split()[1])
        #     try:
        #         client.send(str.encode(str(os.listdir(path)) + '|'))
        #     except:
        #         pass
        # elif command.startswith('rm') and not command.startswith('rm -r'):  # Remove file
        #     path = os.path.join(base_path, command.split()[1])
        #     try:
        #         os.remove(path)
        #     except:
        #         pass
        # elif command.startswith('rm -r'):  # Remove a directory
        #     path = os.path.join(base_path, command.split()[2])
        #     try:
        #         os.rmdir(path)
        #     except:
        #         pass
        # elif command.startswith('edit'):
        #     path = os.path.join(base_path, command.split()[1])
        #     try:
        #         f = open(path, "r")
        #         initial_data = f.read()
        #         edited_data = click.edit(initial_data)
        #         f.close()
        #
        #         with open(path, "w") as f:
        #             f.write(edited_data)
        #             f.close()
        #
        #     except:
        #         pass
        # else:
        #     client.send(str.encode('bad request|'))
        # # mv moonde

    client.close(0)


def threaded_client(client):  # Authentication
    db = sqlite3.connect('server.db')
    os.chdir('Directory')
    cipher = client.recv(2048)
    message = decrypt_cipher(cipher, private_key)
    message_split = message.split('||')
    user_public_key = eval(message_split[0])
    signature = eval(message_split[2])
    timestamp = message_split[1]
    if not rsa.verify(str(f"{user_public_key}||{timestamp}").encode(), signature, user_public_key):
        message = f"M||Wrong Public Key!"
        cipher = encrypt_and_sign(message, private_key, user_public_key)
        client.send(cipher)
        client.close()
    while True:
        message = f"""I||SignUp: 1, Login: 2, Exit: 3"""
        #         message = f"""I$SignUp: 1$first_name$last$name$username$password
        # Login: 2$username$password
        # Exit: 3"""
        cipher = encrypt_and_sign(message, private_key, user_public_key)
        client.send(cipher)
        cipher = client.recv(2048)
        ok, cmd_split = check_sign_and_timestamp(cipher, private_key, user_public_key, client)
        if not ok:
            continue
        cmd_type = cmd_split[0]
        if cmd_type == '1':
            first_name = cmd_split[1]
            last_name = cmd_split[2]
            username = cmd_split[3]
            password = cmd_split[4]
            query = f"""SELECT * FROM 'accounts' WHERE username="{username}" """
            response = db.execute(query).fetchone()
            if response is not None:
                message = 'M||This username is already existed. Please enter another one!'
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                continue
            timestamp = get_timestamp()
            read_token = gen_nonce()
            write_token = gen_nonce()
            query = f"""INSERT INTO dirs (name, parent_id, read_token, write_token, timestamp, base)
            VALUES ("{username}", 1, "{read_token}", "{write_token}", {timestamp}, true)"""
            insert_query(db, query)
            query = f'SELECT * FROM dirs WHERE parent_id=1 and name="{username}"'
            folder = db.execute(query).fetchone()
            folder_id = folder[0]
            query = f"""INSERT INTO accounts 
            VALUES ("{username}", "{first_name}", "{last_name}", "{password}", {folder_id})"""
            insert_query(db, query)
            query = f'INSERT INTO dirs_access VALUES ({folder_id}, "{username}", false, false)'
            insert_query(db, query)
            message = 'M||Registration successful'
            cipher = encrypt_and_sign(message, private_key, user_public_key)
            client.send(cipher)

        elif cmd_type == '2':
            username = cmd_split[1]
            password = cmd_split[2]
            query = f'SELECT * FROM accounts WHERE username="{username}"'
            user = db.execute(query).fetchone()
            if user is None:
                message = 'M||Incorrect username'
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                continue
            username = user[0]
            correct_password = user[3]
            if password == correct_password:
                message = 'M||Login successful'
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                print('Connected : ', username)
                secure_file_system(client, username, user_public_key, db)
            else:
                message = 'M||Incorrect Password'
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                continue  # Back to menu

        elif cmd_type == '3':
            print('client disconnected.|')
            break
        else:
            print("Not understand|")
    client.close()

with open(os.path.join('..', 'server', 'PU_server.pem'), "rb") as f:
    data = f.read()
    public_key = rsa.PublicKey.load_pkcs1(data)
with open(os.path.join('..', 'server', 'PR_server.pem'), "rb") as f:
    data = f.read()
    private_key = rsa.PrivateKey.load_pkcs1(data)

host = ""
port = 0
with open(os.path.join('..', 'client', 'configuration_ip_port'), "r") as f:
    host = f.readline().strip()
    port = int(f.readline().strip())

server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)

try:
    server_socket.bind((host, port))
except socket.error as e:
    print(str(e))

print('Waiting for a connection...')
server_socket.listen(20)

while True:
    Client, address = server_socket.accept()
    client_handler = threading.Thread(
        target=threaded_client,
        args=(Client,)
    )
    client_handler.start()
ServerSocket.close()
