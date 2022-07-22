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


def get_encrypted_folder_name(absolute_path: str, name: str, private_key: rsa.PrivateKey,
                              parent_id: int, db: sqlite3.Connection) -> Optional[str]:
    files_and_folders = os.listdir(absolute_path)
    folder = get_folder_by_name_and_parent(db, name, parent_id)
    folder_id = folder['id']
    for cipher in files_and_folders:
        if not cipher.startswith('.') and os.path.isdir(os.path.join(absolute_path, cipher)):
            raw_id = int(rsa.decrypt(bytes.fromhex(cipher), private_key).decode())
            if folder_id == raw_id:
                return cipher
    return None


def get_encrypted_file_name(absolute_path: str, name: str, private_key: rsa.PrivateKey,
                            folder_id: int, db: sqlite3.Connection) -> Optional[str]:
    files_and_folders = os.listdir(absolute_path)
    file = get_file_by_name_and_folder_id(db, name, folder_id)
    file_id = file['id']
    for cipher in files_and_folders:
        if not cipher.startswith('.') and os.path.isfile(os.path.join(absolute_path, cipher)):
            raw_id = int(rsa.decrypt(bytes.fromhex(cipher), private_key).decode())
            if file_id == raw_id:
                return cipher
    return None


def get_encrypted_absolute_path(absolute_folders: list, private_key: rsa.PrivateKey, db: sqlite3.Connection) -> str:
    res = ''
    for folder in absolute_folders[1:]:
        folder_name = folder['name']
        parent_id = folder['parent_id']
        encrypted_name = get_encrypted_folder_name(os.path.join(os.getcwd(), res), folder_name, private_key,
                                                   parent_id, db)
        # error handling
        res = os.path.join(res, encrypted_name)
    res = os.path.join(os.getcwd(), res)
    return res


def make_empty_file(path, name, content=b''):
    f = open(os.path.join(path, name), 'wb')
    f.write(content)
    f.close()


def get_file_content(path):
    f = open(path, 'rb')
    data = f.read()
    f.close()
    return data


def write_content_to_file(path, content):
    f = open(path, 'wb')
    f.write(content)
    f.close()


def goto_path(db: sqlite3.Connection, client: socket.socket, path: str, current_folder_id: int, username: str,
              private_key: rsa.PrivateKey):
    path_split = path.split(os.path.sep)
    user = get_user_by_username(db, username)
    if path_split[0] == '':
        path_split = path_split[1:]
        user_base_dir = user['base_folder_id']
        current_folder_id = user_base_dir
    for new_folder_name in path_split:
        absolute_path_folders = get_absolute_path_folders(db, current_folder_id)
        absolute_path_encrypted = get_encrypted_absolute_path(absolute_path_folders, private_key, db)
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
                                                      new_folder_name, private_key, current_folder_id, db)
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


def make_file(client: socket.socket, db: sqlite3.Connection, path: str, file_name: str, content: str,
              username: str, folder_id: int,
              public_key: rsa.PublicKey, private_key: rsa.PrivateKey):
    read_token = gen_nonce()
    write_token = gen_nonce()
    insert_into_files(db,
                      file_name=file_name,
                      folder_id=folder_id,
                      read_token=read_token,
                      write_token=write_token)
    file = get_file_by_name_and_folder_id(db, file_name, folder_id)
    file_id = file['id']
    file_name_encrypted = rsa.encrypt(str(file_id).encode(), public_key).hex()
    make_empty_file(path, file_name_encrypted, content)
    file_hash = hash_file(os.path.join(path, file_name_encrypted))
    add_file_to_meta(db, path, file_name_encrypted, file_hash, public_key, private_key)
    insert_into_files_access(db,
                             file_id=file_id,
                             username=username,
                             owner="true",
                             rw="true")
    user = get_user_by_username(db, username)
    user_public_key = eval(user['public_key'])
    message = f"D||set||{file_id}||{write_token}"
    send_message(client, message, user_public_key, private_key)
    sleep(0.5)
    message = f"M||File {file_name} with id {file_id} Created Successfully"
    send_message(client, message, user_public_key, private_key)
    return True


def make_empty_dir(db: sqlite3.Connection, folder_name: str, parent_id: int,
                   public_key: rsa.PublicKey, private_key: rsa.PrivateKey):
    timestamp = get_timestamp()
    insert_into_folders(db,
                        name=folder_name,
                        base="false",
                        parent_id=parent_id,
                        timestamp=timestamp)
    folder = get_folder_by_name_and_parent(db, folder_name, parent_id)
    folder_id = folder['id']
    absolute_path_folder = get_absolute_path_folders(db, parent_id)
    absolute_encrypted_path = get_encrypted_absolute_path(absolute_path_folder, private_key, db)
    new_folder_name_encrypted = rsa.encrypt(str(folder_id).encode(), public_key).hex()
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
                message = f"M||Folder {new_folder_name} with id {new_folder_id} Created Successfully"
                send_message(client, message, user_public_key, private_key)
                exists = True
    if not exists:
        message = "M||Folder Already Exists"
        send_message(client, message, user_public_key, private_key)
    absolute_path_folders = get_absolute_path_folders(db, current_folder_id)
    absolute_path_encrypted = get_encrypted_absolute_path(absolute_path_folders, private_key, db)
    return True, absolute_path_encrypted


def get_list_files_by_folder_id(db: sqlite3.Connection, current_folder_id: int,
                                private_key: rsa.PrivateKey):
    absolute_path_folders = get_absolute_path_folders(db, current_folder_id)
    absolute_path_encrypted = get_encrypted_absolute_path(absolute_path_folders, private_key, db)
    list_files_cipher = os.listdir(absolute_path_encrypted)
    list_files_cipher = filter(lambda x: not x.startswith('.'), list_files_cipher)
    list_files = []
    for cipher in list_files_cipher:
        f_id = rsa.decrypt(bytes.fromhex(cipher), private_key).decode()
        path = os.path.join(absolute_path_encrypted, cipher)
        if os.path.isdir(path):
            folder = get_folder_by_id(db, f_id)
            if folder['parent_id'] == current_folder_id:
                list_files.append(folder['name'])
        elif os.path.isfile(path):
            file = get_file_by_id(db, f_id)
            if file['folder_id'] == current_folder_id:
                list_files.append(file['name'])
    return list_files


def ls(db: sqlite3.Connection, client: socket.socket, path: str, current_folder_id: int,
       username: str, private_key: rsa.PrivateKey):
    res, current_folder_id = goto_path(db, client, path, current_folder_id, username, private_key)
    if res:
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
        absolute_path_encrypted = get_encrypted_absolute_path(absolute_path_folders, private_key, db)
        list_files = filter(lambda x: not x.startswith('.'), os.listdir(absolute_path_encrypted))
        if file_or_folder == 'file':
            file_name_encrypted = get_encrypted_file_name(absolute_path_encrypted, name, private_key, current_folder_id,
                                                          db)
            file_path = os.path.join(absolute_path_encrypted, file_name_encrypted)
            remove_file_from_metadata(db, path, file_name_encrypted, public_key, private_key)
            delete_file_from_database(db, name, current_folder_id)
            os.remove(file_path)
        elif file_or_folder == 'folder':
            folder_name_encrypted = get_encrypted_folder_name(absolute_path_encrypted, name, private_key,
                                                             current_folder_id, db)
            folder_path = os.path.join(absolute_path_encrypted, folder_name_encrypted)
            folder_name = rsa.decrypt(bytes.fromhex(folder_name_encrypted), private_key).decode()
            folder_id = int(rsa.decrypt(bytes.fromhex(folder_name_encrypted), private_key))
            shutil.rmtree(folder_path)
            delete_folder_from_database(db, folder_id)


def mv(db: sqlite3.Connection, client: socket.socket, username: str,
       src_path: str, name: str, dest_path: str, current_folder_id: int, file_or_folder: str,
       public_key: rsa.PublicKey, private_key: rsa.PrivateKey) -> None:
    user = get_user_by_username(db, username)
    user_public_key = eval(user['public_key'])
    res, src_folder_id = goto_path(db, client, src_path, current_folder_id, username, private_key)
    if not res:
        message = "M||CANNOT GO TO SOURCE"
        send_message(client, message, user_public_key, private_key)
    else:
        res, dest_folder_id = goto_path(db, client, dest_path, current_folder_id, username, private_key)
        if not res:
            message = "M||CANNOT GO TO DES"
            send_message(client, message, user_public_key, private_key)
        else:
            absolute_src_path_folders = get_absolute_path_folders(db, src_folder_id)
            absolute_src_path_encrypted = get_encrypted_absolute_path(absolute_src_path_folders, private_key, db)
            absolute_dest_path_folders = get_absolute_path_folders(db, dest_folder_id)
            absolute_dest_path_encrypted = get_encrypted_absolute_path(absolute_dest_path_folders, private_key, db)
            list_files = filter(lambda x: not x.startswith('.'), os.listdir(absolute_src_path_encrypted))
            if file_or_folder == 'file':
                for file_name_cipher in list_files:
                    file_path = os.path.join(absolute_src_path_encrypted, file_name_cipher)
                    file_name = rsa.decrypt(bytes.fromhex(file_name_cipher), private_key).decode()
                    if os.path.isfile(file_path) and file_name == name:
                        file_hash = hash_file(file_path)
                        remove_file_from_metadata(db, absolute_src_path_encrypted, file_name_cipher,
                                                  public_key, private_key)
                        add_file_to_meta(db, absolute_dest_path_encrypted, file_name_cipher, file_hash,
                                         public_key, private_key)
                        update_file_parent_folder(db, name, src_folder_id, dest_folder_id)
                        shutil.move(file_path, absolute_dest_path_encrypted)
            elif file_or_folder == 'folder':
                for folder_name_cipher in list_files:
                    folder_path = os.path.join(absolute_src_path_encrypted, folder_name_cipher)
                    folder_name = rsa.decrypt(bytes.fromhex(folder_name_cipher), private_key).decode()
                    if os.path.isdir(folder_path) and folder_name == name:
                        metadata = get_folder_metadata(folder_path, private_key)
                        folder_id = metadata['folder_id']
                        shutil.move(folder_path, absolute_dest_path_encrypted)
                        update_folder_parent_id(db, folder_id, dest_folder_id)


def check_file_access(db: sqlite3.Connection, client: socket.socket, file_id: int,
                      user_public_key: rsa.PublicKey, private_key: rsa.PrivateKey):
    message = f"D||get||{file_id}"
    send_message(client, message, user_public_key, private_key)
    ok, token = get_message(client, user_public_key, private_key)
    if not ok:
        return False, ''
    token = token[0]
    file = get_file_by_id(db, file_id)
    read_token = file['read_token']
    write_token = file['write_token']
    if token == read_token:
        return True, 'r'
    if token == write_token:
        return True, 'rw'
    return False, ''


def edit(db: sqlite3.Connection, client: socket.socket, username: str, path: str,
         name: str, current_folder_id: int, public_key: rsa.PublicKey, private_key: rsa.PrivateKey) -> None:
    user = get_user_by_username(db, username)
    user_public_key = eval(user['public_key'])
    res, current_folder_id = goto_path(db, client, path, current_folder_id, username, private_key)
    if not res:
        message = "M||CANNOT GO TO PATH"
        send_message(client, message, user_public_key, private_key)
    else:
        absolute_path_folders = get_absolute_path_folders(db, current_folder_id)
        absolute_path_encrypted = get_encrypted_absolute_path(absolute_path_folders, private_key, db)
        file_cipher = get_encrypted_file_name(absolute_path_encrypted, name, private_key, current_folder_id, db)
        file_id = int(rsa.decrypt(bytes.fromhex(file_cipher), private_key).decode())
        file_path = os.path.join(absolute_path_encrypted, file_cipher)
        has_access, access_level = check_file_access(db, client, file_id, user_public_key, private_key)
        if has_access and access_level == 'rw':
            content = get_file_content(file_path)
            message = f"D||edit||{content}"
            send_message(client, message, user_public_key, private_key)
            ok, new_content = get_message(client, user_public_key, private_key)
            if ok:
                write_content_to_file(file_path, eval(new_content[0]))
                new_hash = hash_file(file_path)
                change_file_hash(db, path, file_cipher, new_hash, public_key, private_key)
                message = f"M||File Edited Successfully"
                send_message(client, message, user_public_key, private_key)
            else:
                message = f"M||Write content type"
                send_message(client, message, user_public_key, private_key)
        else:
            message = f"M||You don't have access"
            send_message(client, message, user_public_key, private_key)


def cat(db: sqlite3.Connection, client: socket.socket, username: str, path: str,
        name: str, current_folder_id: int, public_key: rsa.PublicKey, private_key: rsa.PrivateKey) -> None:
    user = get_user_by_username(db, username)
    user_public_key = eval(user['public_key'])
    res, current_folder_id = goto_path(db, client, path, current_folder_id, username, private_key)
    if not res:
        message = "M||CANNOT GO TO PATH"
        send_message(client, message, user_public_key, private_key)
    else:
        absolute_path_folders = get_absolute_path_folders(db, current_folder_id)
        absolute_path_encrypted = get_encrypted_absolute_path(absolute_path_folders, private_key, db)
        file_cipher = get_encrypted_file_name(absolute_path_encrypted, name, private_key, current_folder_id, db)
        file_id = int(rsa.decrypt(bytes.fromhex(file_cipher), private_key).decode())
        file_path = os.path.join(absolute_path_encrypted, file_cipher)
        has_access, access_level = check_file_access(db, client, file_id, user_public_key, private_key)
        if has_access:
            content = get_file_content(file_path)
            message = f"D||cat||{content}"
            send_message(client, message, user_public_key, private_key)


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
            content = eval(cmd_split[2])
            if len(path.split(os.path.sep)) == 1:
                file_name = path
                path = '.'
            else:
                (path, file_name) = os.path.split(path)
            ok, absolute_path_encrypted = mkdir(db, client, user, path, current_folder_id,
                                                public_key, private_key, user_public_key)
            if ok:
                make_file(client, db, absolute_path_encrypted, file_name, content,
                          username, current_folder_id, public_key, private_key)
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
        elif cmd_type == 'mv':
            file_or_folder = cmd_split[1]
            src_path = cmd_split[2]
            if len(src_path.split(os.path.sep)) == 1:
                name = src_path
                src_path = '.'
            else:
                (src_path, name) = os.path.split(src_path)
            dest_path = cmd_split[3]
            mv(db, client, username, src_path, name, dest_path,
               current_folder_id, file_or_folder, public_key, private_key)
        elif cmd_type == 'edit':
            path = cmd_split[1]
            if len(path.split(os.path.sep)) == 1:
                name = path
                path = '.'
            else:
                (path, name) = os.path.split(path)
            edit(db, client, username, path, name, current_folder_id, public_key, private_key)
        elif cmd_type == 'cat':
            path = cmd_split[1]
            if len(path.split(os.path.sep)) == 1:
                name = path
                path = '.'
            else:
                (path, name) = os.path.split(path)
            cat(db, client, username, path, name, current_folder_id, public_key, private_key)
    client.close(0)
