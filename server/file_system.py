import os
import rsa
from time import sleep
from db_utils import *
from meta_utils import *
from utils import *


def get_full_path(db, folder_id):
    res = ''
    while folder_id != 1:
        folder = get_folder_by_id(db, folder_id)
        folder_name = folder[1]
        folder_parent = folder[2]
        res = os.path.join(folder_name, res)
        folder_id = folder_parent
    return res


def find_dir_name(path, name, private_key):
    list_dir = os.listdir(path)
    for cipher in list_dir:
        if os.path.isdir(cipher):
            real_name = rsa.decrypt(bytes.fromhex(cipher), private_key).decode()
            if real_name == name:
                return cipher
    return None


def check_client_has_access_to_dir(db, username, dir_id):
    access = get_folder_access(db, dir_id, username)
    if access is None:
        return False, ''
    access_level = 'rw' if access == 1 else 'r'
    return True, access_level


def make_empty_dir(dir_name, parent_id, db, username, client, user_public_key, public_key, private_key):
    dir_name_encrypted = rsa.encrypt(dir_name.encode(), public_key).hex()
    timestamp = get_timestamp()
    write_token = gen_nonce()
    insert_into_folders(db, dir_name, parent_id, "false", timestamp=timestamp, write_token=write_token)
    folder = get_folder_by_name_and_parent(db, dir_name, parent_id)
    folder_id = folder[0]
    insert_into_folders_acess(db, folder_id, username, "true", "true")
    message = f"D||set||dir||{folder_id}||{write_token}"
    cipher = encrypt_and_sign(message, private_key, user_public_key)
    client.send(cipher)
    os.mkdir(dir_name_encrypted)
    content = f"""{folder_id}
{timestamp}
1"""
    write_meta(os.getcwd(), content, public_key)


def make_path(path, username, db, client, user_public_key, user_base_dir_id, base_path, public_key, private_key):
    path_split = path.split(os.path.sep)
    if path_split[0] == '':
        os.chdir(base_path)
        path_split = path_split[1:]
    for new_folder in path_split:
        metadata = get_folder_metadata(os.getcwd(), private_key)
        folder_id = eval(metadata[0])
        folder_data = get_folder_by_id(db, folder_id)
        folder_base = folder_data[6]
        if new_folder == '.' or new_folder == '':
            continue
        elif new_folder == '..':
            if folder_base != 1:
                os.chdir(os.path.join(os.getcwd(), '..'))
            continue
        parent_id = folder_id if folder_id != 1 else user_base_dir_id
        new_folder_data = get_folder_by_name_and_parent(db, new_folder, parent_id)
        if new_folder_data is not None:
            new_folder_name = find_dir_name(os.getcwd(), new_folder, private_key)
            os.chdir(new_folder_name)
            data_split = get_folder_metadata(os.getcwd(), private_key)
            dir_id = data_split[0]
            access = get_folder_access(db, dir_id, username)
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
            response = get_folder_by_id(db, dir_id)
            nonce = response[4]
            if ticket != nonce:
                message = "M||You don't have required access.\n|"
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                return False
        else:
            make_empty_dir(new_folder, parent_id, db, username, client, user_public_key, public_key, private_key)
    return True


def make_empty_file(path, name):
    f = open(os.path.join(path, name), 'w')
    f.close()


def goto_path(path, base_path, current_dir_id, db, client, username, private_key):
    path_split = path.split(os.path.sep)
    if path_split[0] == '':
        os.chdir(base_path)
        path_split = path_split[1:]
        user = get_user_by_username(db, username)
        user_base_dir = user[4]
        current_dir_id = user_base_dir
        os.chdir(base_path)
    for dir_name in path_split:
        if dir_name == '.' or dir_name == '':
            continue
        elif dir_name == '..':
            metadata = get_folder_metadata(os.getcwd(), private_key)
            parent_dir_id = get_folder_by_id(db, metadata[0])[2]
            if current_dir_id == 1 or parent_dir_id == 1:
                continue
            os.chdir(dir_name)
            metadata = get_folder_metadata(os.getcwd(), private_key)
            current_dir_id = metadata[0]
        else:
            dir_cipher = find_dir_name(os.getcwd(), dir_name, private_key)
            if dir_cipher is None:
                return False, -1
            else:
                os.chdir(dir_cipher)
                metadata = get_folder_metadata(os.getcwd(), private_key)
                current_dir_id = metadata[0]
                if not check_client_has_access_to_dir(db, username, current_dir_id):
                    return False, -1
    return True, current_dir_id


def make_file(path, file_name, username, db, public_key):
    metadata = get_folder_metadata(path, public_key)
    file_name_hash = rsa.encrypt(str.encode(file_name), public_key).hex()
    make_empty_file(path, file_name_hash)
    file_hash = hash_file(file_name_hash)
    folder_id = metadata[0]
    timestamp = get_timestamp()
    metadata[1] = str(timestamp)
    metadata[2] = str(int(metadata[2]) + 1)
    metadata.append(f"{file_name_hash} {file_hash}")
    metadata = "\n".join(metadata)
    write_meta(path, metadata, public_key)
    query = f"""UPDATE dirs
    set timestamp={timestamp}
    WHERE id={folder_id}"""
    insert_update_query(db, query)
    read_token = gen_nonce()
    write_token = gen_nonce()
    query = f"""INSERT INTO files (name, dir_id, read_token, write_token)
    VALUES ('{file_name}', {folder_id}, '{read_token}', '{write_token}')"""
    insert_update_query(db, query)
    query = f"SELECT * FROM files WHERE dir_id={folder_id} and name='{file_name}'"
    file = db.execute(query).fetchone()
    file_id = file[0]
    query = f"""INSERT INTO files_access (file_id, username, owner, rw)
    VALUES ({file_id}, '{username}', true, true)"""
    insert_update_query(db, query)
    return True


def secure_file_system(client, username, user_public_key, db, base_path, public_key, private_key):
    user = get_user_by_username(db, username)
    base_dir_id = user[4]
    current_folder = os.getcwd()
    current_folder_id = 1
    base_dir = get_folder_by_id(db, base_dir_id)
    current_dir_id = base_dir_id
    while True:
        message = f"I||{get_full_path(db, current_dir_id)}>"
        send_message(client, message, user_public_key, private_key)
        ok, cmd_split = get_message(client, user_public_key, private_key)
        if not ok:
            continue
        cmd_type = cmd_split[0]
        if cmd_type == 'mkdir':  # mkdir||path||password||timestamp
            path = cmd_split[1]
            (path, final_dir) = os.path.split(path)
            ra_cwd = os.getcwd()
            res = make_path(path, username, db, client, user_public_key, base_dir_id, base_path, public_key,
                            private_key)
            if res:
                # check folder exists
                message = 'M||Folder Created Successfully'
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                sleep(1)
            os.chdir(ra_cwd)
        elif cmd_type == 'touch':  # touch||path||password||timestamp
            path = cmd_split[1]
            (path, file_name) = os.path.split(path)
            ra_cwd = os.getcwd()
            res = make_path(path, username, db, client, user_public_key, base_dir_id, base_path, public_key,
                            private_key)
            if res:
                res = make_file(os.getcwd(), file_name, username, db, public_key)
                if res:
                    message = 'M||File Created Successfully'
                    cipher = encrypt_and_sign(message, private_key, user_public_key)
                    client.send(cipher)
                    sleep(1)
            os.chdir(ra_cwd)
        elif cmd_type == 'cd':
            ra_cwd = os.getcwd()
            path = cmd_split[1]
            res, cdi = goto_path(path, base_path, current_dir_id, db, client, username, private_key)
            if not res:
                os.chdir(ra_cwd)
                message = f"M||Path doesn't Exist"
                cipher = encrypt_and_sign(message, private_key, user_public_key)
                client.send(cipher)
                sleep(1)
            else:
                current_dir_id = cdi
    client.close(0)
