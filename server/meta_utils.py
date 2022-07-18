import os
from utils import encrypt_message, decrypt_cipher, hash_file


def get_folder_metadata(path, private_key):
    f = open(os.path.join(path, '.meta'), 'rb')
    cipher_data = f.read()
    f.close()
    data = decrypt_cipher(cipher_data, private_key)
    data_split = data.split("\n")
    return data_split


def write_meta(path, content, public_key):
    f = open(os.path.join(path, '.meta'), 'wb')
    f.write(encrypt_message(content, public_key))
    f.close()


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
