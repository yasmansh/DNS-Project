import socket
import threading
import rsa
from rsa import PublicKey, PrivateKey
import click
import sqlite3
from db_utils import *
from utils import send_message, get_message
from meta_utils import *
from file_system import secure_file_system


def check_public_key(client: socket.socket):
    cipher = client.recv(2048)
    message = decrypt_cipher(cipher, private_key)
    message_split = message.split('||')
    user_public_key = eval(message_split[0])
    signature = eval(message_split[2])
    timestamp = message_split[1]
    if not rsa.verify(str(f"{user_public_key}||{timestamp}").encode(), signature, user_public_key):
        message = f"M||Wrong Public Key!\n"
        send_message(client, message, user_public_key, private_key)
        client.close()
        return False, -1
    return True, user_public_key


def signup(client: socket.socket, address: tuple, db: sqlite3.Connection, cmd_split: list,
           user_public_key: rsa.PublicKey) -> None:
    first_name = cmd_split[1]
    last_name = cmd_split[2]
    username = cmd_split[3]
    password = cmd_split[4]
    user = get_user_by_username(db, username)
    (user_host, user_port) = address
    if user is not None:
        message = 'M||This username is already existed. Please enter another one!\n'
        send_message(client, message, user_public_key, private_key)
        return
    insert_into_folders(db,
                        name=username,
                        base="true",
                        )
    folder = get_folder_by_name_and_parent(db,
                                           name=username,
                                           parent_id=None)
    folder_id = folder['id']
    insert_into_accounts(db,
                         username=username,
                         first_name=first_name,
                         last_name=last_name,
                         password=password,
                         base_folder_id=folder_id,
                         public_key=user_public_key,
                         host=user_host,
                         port=user_port)
    message = 'M||Registration successful\n'
    send_message(client, message, user_public_key, private_key)


def login(client: socket.socket, address: tuple, db: sqlite3.Connection, user_public_key, cmd_split: list) -> None:
    username = cmd_split[1]
    password = cmd_split[2]
    (user_host, user_port) = address
    user = get_user_by_username(db, username)
    if user is not None:
        user_public_key = eval(user['public_key'])
        if user is None:
            message = 'M||Incorrect username\n'
            send_message(client, message, user_public_key, private_key)
            return
        correct_password = user['password']
        if password == correct_password:
            message = 'M||Login successful\n'
            update_user(db,
                        username=username,
                        public_key=user_public_key,
                        host=user_host,
                        port=user_port)
            send_message(client, message, user_public_key, private_key)
            print('Connected : ', username)
            secure_file_system(client, username, db, user_public_key, public_key, private_key)
        else:
            message = 'M||Incorrect Password\n'
            send_message(client, message, user_public_key, private_key)
            return  # Back to menu
    else:
        message = f"M||Incorrect username\n"
        send_message(client, message, user_public_key, private_key)


def threaded_client(client: socket.socket, address):  # Authentication
    db = sqlite3.connect('../server.db')
    db.execute("PRAGMA foreign_keys = ON")
    valid_public_key, user_public_key = check_public_key(client)
    if not valid_public_key:
        return
    while True:
        message = f"""I||SignUp: 1, Login: 2, Exit: 3\n"""
        send_message(client, message, user_public_key, private_key)
        ok, cmd_split = get_message(client, user_public_key, private_key)
        if not ok:
            continue
        cmd_type = cmd_split[0]
        if cmd_type == '1':
            signup(client, address, db, cmd_split, user_public_key)
        elif cmd_type == '2':
            login(client, address, db, user_public_key, cmd_split)
        elif cmd_type == '3':
            print('client disconnected.|')
            break
        else:
            # send message to client
            print("Not understand|")
    client.close()


def main():
    os.chdir('Directory')
    server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    try:
        server_socket.bind((host, port))
    except socket.error as e:
        print(str(e))

    print('Waiting for a connection...')
    server_socket.listen(20)

    while True:
        client, address = server_socket.accept()
        print(address)
        client_handler = threading.Thread(
            target=threaded_client,
            args=(client, address)
        )
        client_handler.start()


if __name__ == '__main__':
    with open(os.path.join('PU_server.pem'), "rb") as f:
        data = f.read()
        public_key = rsa.PublicKey.load_pkcs1(data)
    with open(os.path.join('PR_server.pem'), "rb") as f:
        data = f.read()
        private_key = rsa.PrivateKey.load_pkcs1(data)
    with open(os.path.join('..', 'client', 'configuration_ip_port'), "r") as f:
        host = f.readline().strip()
        port = int(f.readline().strip())

    main()
