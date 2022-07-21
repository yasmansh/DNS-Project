import os
import socket
import sqlite3
from typing import Optional
import shutil
import rsa
from rsa import PublicKey
from time import sleep
from db_utils import *
from meta_utils import *
from utils import *


def get_absolute_path_folders(db: sqlite3.Connection, folder_id: int) -> list:
    res = []
    folder = get_folder_by_id(db, folder_id)
    while folder is not None:
        res.append(folder)
        folder_id = folder['parent_id']
        folder = get_folder_by_id(db, folder_id)
    res.reverse()
    return res


def get_relative_path_string(absolute_folders: list) -> str:
    res = ''
    for folder in absolute_folders:
        res = os.path.join(res, folder['name'])
    return res


def get_absolute_path_string(absolute_folders: list) -> str:
    res = get_relative_path_string(absolute_folders)
    res = os.path.join(os.getcwd(), res)
    return res


def get_encrypted_folder_name(absolute_path: str, name: str, private_key: rsa.PrivateKey) -> Optional[str]:
    files_and_folders = os.listdir(absolute_path)
    for cipher in files_and_folders:
        if not cipher.startswith('.') and os.path.isdir(os.path.join(absolute_path, cipher)):
            raw_name = rsa.decrypt(bytes.fromhex(cipher), private_key).decode()
            if name == raw_name:
                return cipher
    return None


def get_encrypted_absolute_path(absolute_folders: list, private_key: rsa.PrivateKey) -> str:
    res = ''
    for folder in absolute_folders[1:]:
        folder_name = folder['name']
        encrypted_name = get_encrypted_folder_name(os.path.join(os.getcwd(), res), folder_name, private_key)
        # error handling
        res = os.path.join(res, encrypted_name)
    res = os.path.join(os.getcwd(), res)
    return res


def make_empty_file(path, name):
    f = open(os.path.join(path, name), 'w')
    f.close()


def goto_path(db: sqlite3.Connection, client: socket.socket, path: str, current_folder_id: int, username: str,
              private_key: rsa.PrivateKey):
    path_split = path.split(os.path.sep)
    user = get_user_by_username(db, username)
    if path_split[0] == '':
        path_split = path_split[1:]
        user_base_dir = user['base_folder_id']
        current_folder_id = user_base_dir
    absolute_path_folders = get_absolute_path_folders(db, current_folder_id)
    absolute_path_encrypted = get_encrypted_absolute_path(absolute_path_folders, private_key)
    for new_folder_name in path_split:
        if new_folder_name == '.' or new_folder_name == '':
            continue
        folder = get_folder_by_id(db, current_folder_id)
        parent_folder_id = folder['parent_id']
        if new_folder_name == '..':
            if parent_folder_id is None:
                continue
            current_folder_id = parent_folder_id
        else:
            folder_cipher = get_encrypted_folder_name(absolute_path_encrypted,
                                                      new_folder_name, private_key)
            if folder_cipher is None:
                message = f"Folder {new_folder_name} Doesn't Exists"
                user_public_key = eval(user['public_key'])
                send_message(client, message, user_public_key, private_key)
                return False, -1
            else:
                absolute_path_encrypted = os.path.join(absolute_path_encrypted, folder_cipher)
                metadata = get_folder_metadata(absolute_path_encrypted, private_key)
                current_folder_id = metadata['folder_id']
    return True, current_folder_id


def make_file(client: socket.socket, db: sqlite3.Connection, path: str, file_name: str, username: str,
              public_key: rsa.PublicKey, private_key: rsa.PrivateKey):
    file_name_encrypted = rsa.encrypt(str.encode(file_name), public_key).hex()
    make_empty_file(path, file_name_encrypted)
    file_hash = hash_file(os.path.join(path, file_name_encrypted))
    metadata = get_folder_metadata(path, private_key)
    folder_id = metadata['folder_id']
    add_file_to_meta(db, path, file_name_encrypted, file_hash, public_key, private_key)
    read_token = gen_nonce()
    write_token = gen_nonce()
    insert_into_files(db,
                      file_name=file_name,
                      folder_id=folder_id,
                      read_token=read_token,
                      write_token=write_token)
    file = get_file_by_name_and_folder_id(db, file_name, folder_id)
    file_id = file['id']
    insert_into_files_access(db,
                             file_id=file_id,
                             username=username,
                             owner="true",
                             rw="true")
    user = get_user_by_username(db, username)
    user_public_key = eval(user['public_key'])
    message = f"M||File with id {file_id} Created Successfully"
    send_message(client, message, user_public_key, private_key)
    return True


def make_empty_dir(db: sqlite3.Connection, folder_name: str, parent_id: int,
                   public_key: rsa.PublicKey, private_key: rsa.PrivateKey):
    absolute_path_folder = get_absolute_path_folders(db, parent_id)
    absolute_encrypted_path = get_encrypted_absolute_path(absolute_path_folder, private_key)
    new_folder_name_encrypted = rsa.encrypt(folder_name.encode(), public_key).hex()
    timestamp = get_timestamp()
    insert_into_folders(db,
                        name=folder_name,
                        base="false",
                        parent_id=parent_id,
                        timestamp=timestamp)
    folder = get_folder_by_name_and_parent(db, folder_name, parent_id)
    folder_id = folder['id']
    new_folder_absolute_path = os.path.join(absolute_encrypted_path, new_folder_name_encrypted)
    os.mkdir(new_folder_absolute_path)
    content = f"""{folder_id}
{timestamp}
1"""
    write_meta(new_folder_absolute_path, content, public_key)
    return True, folder_id


def mkdir(db: sqlite3.Connection, client: socket.socket, user: dict, path: str, current_folder_id: int,
          public_key: rsa.PublicKey, private_key: rsa.PrivateKey, user_public_key: rsa.PublicKey) -> tuple:
    path_split = path.split(os.path.sep)
    exists = False
    if path_split[0] == '':
        current_folder_id = user['base_folder_id']
        path_split = path_split[1:]
    for new_folder_name in path_split:
        folder = get_folder_by_id(db, current_folder_id)
        folder_id = folder['id']
        folder_parent_id = folder['parent_id'] if folder is not None else user['base_folder_id']
        if new_folder_name == '.' or new_folder_name == '':
            continue
        elif new_folder_name == '..':
            if folder_parent_id is not None:
                current_folder_id = folder_parent_id
            continue
        new_folder = get_folder_by_name_and_parent(db, new_folder_name, folder_id)
        if new_folder is not None:
            current_folder_id = new_folder['id']
        else:
            ok, new_folder_id = make_empty_dir(db, new_folder_name, folder_id, public_key, private_key)
            if ok:
                current_folder_id = new_folder_id
                message = f"M||Folder with id {new_folder_id} Created Successfully"
                send_message(client, message, user_public_key, private_key)
                exists = True
    if not exists:
        message = "M||Folder Already Exists"
        send_message(client, message, user_public_key, private_key)
    absolute_path_folders = get_absolute_path_folders(db, current_folder_id)
    absolute_path_encrypted = get_encrypted_absolute_path(absolute_path_folders, private_key)
    return True, absolute_path_encrypted


def get_list_files_by_folder_id(db: sqlite3.Connection, current_folder_id: int,
                                private_key: rsa.PrivateKey):
    absolute_path_folders = get_absolute_path_folders(db, current_folder_id)
    absolute_path_encrypted = get_encrypted_absolute_path(absolute_path_folders, private_key)
    list_files_cipher = os.listdir(absolute_path_encrypted)
    list_files_cipher = filter(lambda x: not x.startswith('.'), list_files_cipher)
    list_files = [rsa.decrypt(bytes.fromhex(i), private_key).decode() for i in list_files_cipher]
    return list_files


def ls(db: sqlite3.Connection, client: socket.socket, path: str, current_folder_id: int,
       username: str, private_key: rsa.PrivateKey):
    res, cdi = goto_path(db, client, path, current_folder_id, username, private_key)
    if res:
        current_folder_id = cdi
        list_files = get_list_files_by_folder_id(db, current_folder_id, private_key)
        seperator = '\n'
        list_files_string = seperator.join(list_files)
        message = f"M||{list_files_string}"
        user = get_user_by_username(db, username)
        user_public_key = eval(user['public_key'])
        send_message(client, message, user_public_key, private_key)


def rm(db: sqlite3.Connection, client: socket.socket, path: str, username: str,
       current_folder_id: int, name: str, file_or_folder: str,
       public_key: rsa.PublicKey, private_key: rsa.PrivateKey) -> None:
    res, current_folder_id = goto_path(db, client, path, current_folder_id, username, private_key)
    if res:
        absolute_path_folders = get_absolute_path_folders(db, current_folder_id)
        absolute_path_encrypted = get_encrypted_absolute_path(absolute_path_folders, private_key)
        list_files = filter(lambda x: not x.startswith('.'), os.listdir(absolute_path_encrypted))
        metadata = get_folder_metadata(absolute_path_encrypted, private_key)
        folder_id = metadata['folder_id']
        if file_or_folder == 'file':
            for file_name_cipher in list_files:
                file_path = os.path.join(absolute_path_encrypted, file_name_cipher)
                file_name = rsa.decrypt(bytes.fromhex(file_name_cipher), private_key).decode()
                if os.path.isfile(file_path) and file_name == name:
                    remove_file_from_metadata(db, path, file_name_cipher, public_key, private_key)
                    delete_file_from_database(db, file_name, folder_id)
                    os.remove(file_path)
        elif file_or_folder == 'folder':
            for folder_name_cipher in list_files:
                folder_path = os.path.join(absolute_path_encrypted, folder_name_cipher)
                folder_name = rsa.decrypt(bytes.fromhex(folder_name_cipher), private_key).decode()
                if os.path.isdir(folder_path) and folder_name == name:
                    metadata = get_folder_metadata(folder_path, private_key)
                    folder_id = metadata['folder_id']
                    shutil.rmtree(folder_path)
                    delete_folder_from_database(db, folder_id)


def secure_file_system(client: socket.socket, username: str, db: sqlite3.Connection, user_public_key: rsa.PublicKey,
                       public_key: rsa.PublicKey, private_key: rsa.PrivateKey):
    user = get_user_by_username(db, username)
    base_folder_id = user['base_folder_id']
    current_folder_id = base_folder_id
    while True:
        absolute_path_folders = get_absolute_path_folders(db, current_folder_id)
        message = f"I||{get_relative_path_string(absolute_path_folders)}>"
        send_message(client, message, user_public_key, private_key)
        ok, cmd_split = get_message(client, user_public_key, private_key)
        if not ok:
            continue
        cmd_type = cmd_split[0]
        if cmd_type == 'mkdir':  # mkdir||path||password||timestamp
            path = cmd_split[1]
            mkdir(db, client, user, path, current_folder_id, public_key, private_key, user_public_key)
        elif cmd_type == 'touch':  # touch||path||password||timestamp
            path = cmd_split[1]
            if len(path.split(os.path.sep)) == 1:
                file_name = path
                path = '.'
            else:
                (path, file_name) = os.path.split(path)
            ok, absolute_path_encrypted = mkdir(db, client, user, path, current_folder_id,
                                                public_key, private_key, user_public_key)
            if ok:
                make_file(client, db, absolute_path_encrypted, file_name, username, public_key, private_key)
        elif cmd_type == 'cd':
            path = cmd_split[1]
            res, cdi = goto_path(db, client, path, current_folder_id, username, private_key)
            if res:
                current_folder_id = cdi
        elif cmd_type == 'ls':
            path = cmd_split[1]
            ls(db, client, path, current_folder_id, username, private_key)
        elif cmd_type == 'rm':
            file_or_folder = cmd_split[1]
            path = cmd_split[2]
            if len(path.split(os.path.sep)) == 1:
                name = path
                path = '.'
            else:
                (path, name) = os.path.split(path)
            rm(db, client, path, username, current_folder_id, name, file_or_folder,
               public_key, private_key)
    client.close(0)
