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
from utils import get_timestamp, check_freshness, create_empty_dir, encrypt_message, random_string, decrypt_cipher


def allocate_empty_dir(db, username, first_name, last_name, password, user_public_key):
    query = "SELECT * FROM dirs WHERE empty=true"
    response = db.execute(query)
    row = response.fetchone()
    dir_id = row[0]
    name = f"{username}$basedir"
    name = str(rsa.encrypt(name.encode(), public_key))
    query = f"""UPDATE dirs
                        SET empty=false, name="{name}"
                        WHERE id={dir_id}"""
    db.execute(query)
    db.commit()
    query = f"""INSERT INTO dirs_access (dir_id, username, owner, rw)
                        VALUES ({dir_id}, "{username}", true, true)"""
    db.execute(query)
    db.commit()
    query = f"""INSERT INTO accounts (username, first_name, last_name, password, 
                            public_key, base_dir)
                            VALUES ("{username}", "{first_name}", "{last_name}", "{password}", "{user_public_key}",
                            {dir_id}
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


def check_meta(path, timestamp):
    f = open(os.path.join(path, '.meta'))
    cipher_data = f.read()
    f.close()
    data = decrypt_cipher(cipher_data, private_key)
    data_split = data.split("\n")
    list_dir = os.listdir(path)
    if len(list_dir) != data_split[1] or timestamp != data_split[2]:
        return False
    for row in data_split[3:]:
        name_hash = row.split('$')
        file_name = name_hash[0]
        file_hash = name_hash[1]
        file_path = os.path.join(path, file_name)
        if not os.path.exists(file_path) or hash_file(file_path) != file_hash:
            return False
    return True


def make_path(path, username, db, client, user_public_key):
    path_split = path.split(os.path.sep)
    for folder in path_split:
        f = open(os.path.join(os.getcwd(), '.meta'), 'rb')
        cipher_data = f.read()
        f.close()
        data = decrypt_cipher(cipher_data, private_key)
        data_split = data.split("\n")
        folder_id = data_split[0]
        folder_name = rsa.encrypt(str.encode(f"{username}${folder}"), public_key)
        flag_path = os.path.join(os.getcwd(), folder_name)
        if os.path.exists(flag_path):
            os.chdir(flag_path)
            f = open(os.path.join(os.getcwd(), '.meta'), 'rb')
            cipher_data = f.read()
            f.close()
            data = decrypt_cipher(cipher_data, private_key)
            data_split = data.split("\n")
            folder_id = data_split[0]
            query = f"""SELECT * FROM dirs_access
            WHERE id={folder_id}, username="{username}" """
            response = db.execute(query)
            access = response.fetchone()
            rw = access[3]
            if rw == 0:
                client.send(str.encode("You don't have required access.\n|"))
                return False
            message = f"Send Folder Ticket${folder_id}${get_timestamp()}"
            client.send(encrypt_message(message, user_public_key))
            message = client.recv(2048)
            message = decrypt_cipher(message, private_key)
            message_split = message.split('$')
            ticket = message_split[0]
            timestamp = message_split[1]
            if not check_freshness(timestamp):
                client.send(str.encode("Please try again later.\n|"))
                return False
            query = f"""SELECT * FROM dirs
            WHERE id={folder_id}"""
            response = db.execute(query)
            response = response.fetchone()
            nonce = response[3]
            if ticket != nonce:
                client.send(str.encode("You don't have required access.\n|"))
                return False
        else:
            ts = get_timestamp()
            folder_name = rsa.encrypt(str.encode(f"{username}${folder}"), public_key)
            nonce = hashlib.sha256(str.encode(random_string(64)))
            db.execute(f"""INSERT INTO dirs (name, parent_id, nonce, timestamp, empty)
                        VALUES ("{folder_name}", {folder_id}, "{nonce}", {ts}, false)""")
            db.commit()
            query = f"""SELECT * FROM dirs
                    WHERE name="{folder_name}" and parent_id={folder_id}
                    """
            response = db.execute(query)
            response = response.fetchone()
            folder = response.fetchone()
            folder_id = folder[0]
            os.mkdir(folder_name)
            os.chdir(folder_name)
            f = open('.meta', 'ab')
            message = f"""{folder_id}
{ts}
0"""
            f.write(encrypt_message(message, public_key))
            f.close()
        message = f"Completed${get_timestamp()}"
        message = encrypt_message(message, user_public_key)
        client.send(message)
        return True


def secure_file_system(client, username, user_public_key, db):
    pre_len = os.getcwd().__len__()
    query = f'SELECT * FROM accounts WHERE username="{username}"'
    response = db.execute(query)
    user = response.fetchone()
    correct_password = user[3]
    base_dir_id = user[5]
    query = f"SELECT * FROM dirs WHERE id={base_dir_id}"
    response = db.execute(query)
    base_dir = response.fetchone()
    base_dir_name = base_dir[1]
    base_dir_ts = base_dir[4]
    base_path = os.path.join(os.getcwd(), 'Directory', base_dir_name)

    while True:
        client.send(str.encode('\n' + username + ':' + base_path[pre_len:] + '>'))
        message = client.recv(2048)
        command = decrypt_cipher(message, private_key)
        command_split = command.split('$')
        if not check_freshness(command_split[-1]):
            client.send(str.encode('Please try again later.\n|'))
            return
        command_type = command_split[0]
        if command_type == 'mkdir':  # mkdir$path$password$timestamp
            path = command_split[1]
            password = command_split[2]
            if password != correct_password:
                client.send(str.encode('Please try again later.\n|'))
                return
            make_path(os.path.normpath(path), username, db, client, user_public_key)
        elif command.startswith('touch'):
            path = command.split()[1]
            if path.__contains__('\\') or path.__contains__('/'):
                ps = path.split('\\')
                ps = ps.split('/')
                path = os.path.join(base_path, ps[0])
                if os.path.exists(path):
                    pass
                else:
                    os.mkdir(path)
                for i in range(1, len(ps) - 1):
                    path = os.path.join(path, ps[i])
                    if os.path.exists(path):
                        pass
                    else:
                        os.mkdir(path)
                path = os.path.join(path, ps[-1])
                if os.path.exists(path):
                    os.utime(path, None)
                else:
                    open(path, 'a').close()
            else:
                path = os.path.join(base_path, path)
                if os.path.exists(path):
                    os.utime(path, None)
                else:
                    open(path, 'a').close()
        elif command.startswith('cd'):
            path = os.path.join(base_path, command.split()[1])
            try:
                os.chdir(path)
                base_path = os.getcwd()
            except:
                client.send(str.encode('error|'))
                pass
        elif command == 'ls':
            client.send(str.encode(str(os.listdir(base_path)) + '|'))
        elif command.startswith('ls'):
            path = os.path.join(base_path, command.split()[1])
            try:
                client.send(str.encode(str(os.listdir(path)) + '|'))
            except:
                pass
        elif command.startswith('rm') and not command.startswith('rm -r'):  # Remove file
            path = os.path.join(base_path, command.split()[1])
            try:
                os.remove(path)
            except:
                pass
        elif command.startswith('rm -r'):  # Remove a directory
            path = os.path.join(base_path, command.split()[2])
            try:
                os.rmdir(path)
            except:
                pass
        elif command.startswith('edit'):
            path = os.path.join(base_path, command.split()[1])
            try:
                f = open(path, "r")
                initial_data = f.read()
                edited_data = click.edit(initial_data)
                f.close()

                with open(path, "w") as f:
                    f.write(edited_data)
                    f.close()

            except:
                pass
        else:
            client.send(str.encode('bad request|'))
        # mv moonde

    client.close(0)


def access_control(client):
    client.send(str.encode(
        str(user_securityLevel) + '\nPlease Enter username #security level(1.Top secret, 2.secret, 3.Unclassified):'))
    command = rsa.decrypt(client.recv(2048), private_key).decode()
    if not check_freshness(command):
        client.send(str.encode('Please try again later.\n|'))
        return
    u, l = command.split()
    print(command.split())
    if l == '1':
        user_securityLevel[u] = 'Top secret'
    elif l == '2':
        user_securityLevel[u] = 'Secret'
    else:
        user_securityLevel[u] = 'Unclassified'
    pass


def threaded_client(client):  # Authentication
    db = sqlite3.connect('server.db')
    while True:
        client.send(str.encode(
            'SingUp: 1$first_name$last_name$username$password\n' +
            # 1$first_name$last_name$username$H(password)$public_key$sign$timestamp
            "Login: 2$username$password\n" +
            # 2$username$H(password)$timestamp
            'Exit: 3')
            # 3$timestamp
        )

        message = client.recv(2048)
        command = decrypt_cipher(message, private_key)
        command_split = command.split('$')
        cmd_type = command_split[0]
        if not check_freshness(command_split[-1]):
            client.send(str.encode('Please try again later.\n|'))
            continue

        if cmd_type == '1':
            first_name = command_split[1]
            last_name = command_split[2]
            username = command_split[3]
            password = command_split[4]
            user_public_key = command_split[5]
            signature = eval(command_split[6])
            query = f'SELECT * FROM accounts WHERE username="{username}"'
            response = db.execute(query)
            if len(response.fetchall()) != 0:
                client.send(str.encode('This username is already existed. Please enter another one!\n'))
                continue
            if rsa.verify(str(user_public_key).encode(), signature, eval(user_public_key)):
                db.execute(query)
                db.commit()
                r = random.random()
                if r <= 1/3:
                    allocate_empty_dir(db, username, first_name, last_name, password, user_public_key)
                elif r <= 2/3:
                    create_empty_dir(os.path.join(os.getcwd(), 'Directory'), db, public_key)
                    allocate_empty_dir(db, username, first_name, last_name, password, user_public_key)
                else:
                    create_empty_dir(os.path.join(os.getcwd(), 'Directory'), db, public_key)
                    create_empty_dir(os.path.join(os.getcwd(), 'Directory'), db, public_key)
                    allocate_empty_dir(db, username, first_name, last_name, password, user_public_key)
                client.send(str.encode('Registration successful|'))
            else:
                client.send(str.encode('Invalid Signature|'))
            continue  # Back to menu

        elif cmd_type == '2':
            username = command_split[1]
            password = command_split[2]

            query = f'SELECT * FROM accounts WHERE username="{username}"'
            response = db.execute(query)
            user = response.fetchone()
            if user is None:
                client.send(str.encode('Incorrect username.|\n'))
                continue
            username = user[0]
            correct_password = user[3]
            user_public_key = eval(user[4])
            if password == correct_password:
                client.send(str.encode('Login successful|'))
                print('Connected : ', username)
                secure_file_system(client, username, user_public_key, db)
            else:
                client.send(str.encode('Incorrect username or password.|\n'))
                continue  # Back to menu

        elif command == '3':
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
os.chdir('Directory')

while True:
    Client, address = server_socket.accept()
    client_handler = threading.Thread(
        target=threaded_client,
        args=(Client,)
    )
    client_handler.start()
ServerSocket.close()
