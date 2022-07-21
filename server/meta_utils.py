import os
import sqlite3

import rsa
from utils import encrypt_message, decrypt_cipher, hash_file, get_timestamp
from db_utils import update_folder_timestamp


def get_folder_metadata(path, private_key):
    f = open(os.path.join(path, '.meta'), 'rb')
    cipher_data = f.read()
    f.close()
    data = decrypt_cipher(cipher_data, private_key)
    data_split = data.split("\n")
    data_dict = {
        'folder_id': data_split[0],
        'timestamp': data_split[1],
        'number_of_files': data_split[2],
        'hashes': data_split[3:],
    }
    return data_dict


def write_meta(path, content, public_key):
    f = open(os.path.join(path, '.meta'), 'wb')
    f.write(encrypt_message(content, public_key))
    f.close()


def convert_metadata_dict_to_list(metadata: dict) -> list:
    res = [metadata['folder_id'],
           metadata['timestamp'],
           metadata['number_of_files']]
    res += metadata['hashes']
    return res


def add_file_to_meta(db: sqlite3.Connection, path: str, file_name_encrypted: str, file_hash: str,
                     public_key: rsa.PublicKey, private_key: rsa.PrivateKey) -> None:
    metadata = get_folder_metadata(path, private_key)
    timestamp = get_timestamp()
    metadata['timestamp'] = str(timestamp)
    folder_id = metadata['folder_id']
    number_of_files = int(metadata['number_of_files'])
    number_of_files += 1
    metadata['number_of_files'] = str(number_of_files)
    new_row = f"{file_name_encrypted} {file_hash}"
    metadata['hashes'].append(new_row)
    metadata = convert_metadata_dict_to_list(metadata)
    seperator = "\n"
    content = seperator.join(metadata)
    write_meta(path, content, public_key)
    update_folder_timestamp(db, folder_id, timestamp)


def check_meta(path, timestamp, private_key):
    data_split = get_folder_metadata(path, private_key)
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
