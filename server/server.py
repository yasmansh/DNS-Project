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

import client.main
from utils import get_timestamp, create_empty_dir, random_string, decrypt_cipher, encrypt_and_sign, \
    check_sign_and_timestamp, encrypt_message


def allocate_empty_dir(db, username, first_name, last_name, password, user_public_key):
    query = "SELECT * FROM dirs WHERE empty=true"
    row = db.execute(query).fetchone()
    dir_id = row[0]
    dir_name = row[1]
    name = f"{username}||Directory"
    name = rsa.encrypt(name.encode(), public_key).hex()
    os.rename(dir_name, name)
    query = f"""UPDATE dirs
                        SET empty=false, name="{name}"
                        WHERE id={dir_id}"""
    db.execute(query)
    db.commit()
    query = f"""INSERT INTO dirs_access (dir_id, username, owner, rw)
                        VALUES ({dir_id}, "{username}", true, true)"""
    db.execute(query)
    db.commit()
    query = f"""INSERT INTO accounts (username, first_name, last_name, password, base_dir)
                            VALUES ("{username}", "{first_name}", "{last_name}", "{password}", {dir_id}
                            )"""
    db.execute(query)
    db.commit()


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


def write_meta(path, content, public_key):
    f = open(os.path.join(path, '.meta'), 'wb')
    f.write(encrypt_message(content, public_key))
    f.close()


def make_path(path, username, db, client, user_public_key):
    metadata = get_folder_metadata(os.getcwd())
    folder_id = metadata[0]
    path_split = path.split(os.path.sep)
    for folder in path_split:
        folder_name = rsa.encrypt(folder.encode(), public_key).hex()
        flag_path = os.path.join(os.getcwd(), folder_name)
        if os.path.exists(flag_path):
            os.chdir(flag_path)
            data_split = get_folder_metadata(os.getcwd())
            dir_id = data_split[0]
            query = f"""SELECT * FROM dirs_access
            WHERE id={dir_id}, username="{username}" """
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
            ok, message = check_sign_and_timestamp(cipher, private_key, user_public_key)
            if not ok:
                client.send(encrypt_and_sign(message, private_key, user_public_key))
                continue
            message_split = message.split('||')
            ticket = message_split[0]
            query = f"""SELECT * FROM dirs
            WHERE id={dir_id}"""
            response = db.execute(query).fetchone()
            nonce = response[3]
            if ticket != nonce:
                message = "M||You don't have required access.\n|"
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                return False
        else:
            nonce = hashlib.sha256(str.encode(random_string(64)))
            timestamp = get_timestamp()
            db.execute(f"""INSERT INTO dirs (name, parent_id, nonce, timestamp, empty)
                        VALUES ("{folder_name}", {folder_id}, "{nonce}", {timestamp}, false)""")
            db.commit()
            query = f"""SELECT * FROM dirs
                    WHERE name="{folder_name}" and parent_id={folder_id}
                    """
            response = db.execute(query)
            folder = response.fetchone()
            folder_id = folder[0]
            os.mkdir(folder_name)
            os.chdir(folder_name)
            content = f"""{folder_id}
{timestamp}
1"""
            write_meta(os.getcwd(), content, public_key)
        return True


def secure_file_system(client, username, user_public_key, db):
    pre_len = os.getcwd().__len__()
    query = f'SELECT * FROM accounts WHERE username="{username}"'
    response = db.execute(query)
    user = response.fetchone()
    base_dir_id = user[4]
    query = f"SELECT * FROM dirs WHERE id={base_dir_id}"
    response = db.execute(query)
    base_dir = response.fetchone()
    base_dir_name = base_dir[1]
    base_path = os.path.join(os.getcwd(), base_dir_name)
    os.chdir(base_path)
    while True:
        message = f"I||{username}: {base_path[pre_len:]}>"
        cipher = encrypt_and_sign(message, private_key, user_public_key)
        client.send(cipher)
        cipher = client.recv(2048)
        ok, cmd = check_sign_and_timestamp(cipher, private_key, user_public_key)
        if not ok:
            client.send(encrypt_and_sign(cmd, private_key, user_public_key))
            continue
        cmd_split = cmd.split('||')
        cmd_type = cmd_split[0]
        if cmd_type == 'mkdir':  # mkdir$path$password$timestamp
            path = cmd_split[1]
            res = make_path(os.path.normpath(path), username, db, client, user_public_key)
            if res:
                message = 'M||Folder Created Successfully'
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
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


# def access_control(client):
#     client.send(str.encode(
#         str(user_securityLevel) + '\nPlease Enter username #security level(1.Top secret, 2.secret, 3.Unclassified):'))
#     command = rsa.decrypt(client.recv(2048), private_key).decode()
#     if not check_freshness(command):
#         client.send(str.encode('Please try again later.\n|'))
#         return
#     u, l = command.split()
#     if l == '1':
#         user_securityLevel[u] = 'Top secret'
#     elif l == '2':
#         user_securityLevel[u] = 'Secret'
#     else:
#         user_securityLevel[u] = 'Unclassified'
#     pass


def threaded_client(client):  # Authentication
    db = sqlite3.connect('server.db')
    os.chdir('Directory')
    cipher = client.recv(2048)
    message = decrypt_cipher(cipher, private_key)
    message_split = message.split('||')
    user_public_key = eval(message_split[0])
    print(message_split)
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
        ok, cmd = check_sign_and_timestamp(cipher, private_key, user_public_key)
        print(cmd)
        if not ok:
            client.send(encrypt_and_sign(message, private_key, user_public_key))
            continue
        cmd_split = cmd.split('||')
        cmd_type = cmd_split[0]
        if cmd_type == '1':
            first_name = cmd_split[1]
            last_name = cmd_split[2]
            username = cmd_split[3]
            password = cmd_split[4]
            query = f"""SELECT * FROM 'accounts' WHERE username="{username}" """
            response = db.execute(query)
            if len(response.fetchall()) != 0:
                message = 'M||This username is already existed. Please enter another one!\n'
                cipher = encrypt_and_sign(message, private_key, public_key)
                client.send(cipher)
                continue
            db.execute(query)
            r = random.random()
            if r <= 1 / 3:
                allocate_empty_dir(db, username, first_name, last_name, password, user_public_key)
            elif r <= 2 / 3:
                create_empty_dir(os.path.join(os.getcwd()), db, public_key)
                allocate_empty_dir(db, username, first_name, last_name, password, user_public_key)
            else:
                create_empty_dir(os.path.join(os.getcwd()), db, public_key)
                create_empty_dir(os.path.join(os.getcwd()), db, public_key)
                allocate_empty_dir(db, username, first_name, last_name, password, user_public_key)
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
user_pass = {}
user_securityLevel = {}  # Top secret , Secret , Unclassified
user_info = []  # (username, first_name, last_name)

while True:
    Client, address = server_socket.accept()
    client_handler = threading.Thread(
        target=threaded_client,
        args=(Client,)
    )
    client_handler.start()
ServerSocket.close()
