import sqlite3

import rsa

from utils import get_timestamp, gen_nonce


def get_user_by_username(db: sqlite3.Connection, username: str) -> dict:
    query = f'SELECT * FROM accounts WHERE username="{username}"'
    user_tuple = db.execute(query).fetchone()
    user_dict = {
        'username': user_tuple[0],
        'first_name': user_tuple[1],
        'last_name': user_tuple[2],
        'password': user_tuple[3],
        'base_folder_id': user_tuple[4],
        'public_key': user_tuple[5],
        'host': user_tuple[6],
        'ip': user_tuple[7],
    } if user_tuple is not None else None
    return user_dict


def folder_tuple_to_folder_dict(folder_tuple: tuple) -> dict:
    folder_dict = {
        'id': folder_tuple[0],
        'name': folder_tuple[1],
        'parent_id': folder_tuple[2],
        'read_token': folder_tuple[3],
        'write_token': folder_tuple[4],
        'timestamp': folder_tuple[5],
        'is_base': folder_tuple[6],
    } if folder_tuple is not None else None
    return folder_dict


def get_folder_by_id(db: sqlite3.Connection, folder_id: int):
    query = f"SELECT * FROM folders WHERE id={folder_id}"
    folder_tuple = db.execute(query).fetchone()
    folder_dict = folder_tuple_to_folder_dict(folder_tuple)
    return folder_dict


def get_folder_by_name_and_parent(db: sqlite3.Connection, name: str, parent_id: int):
    query = f'SELECT * FROM folders WHERE name="{name}" and parent_id={parent_id}'
    folder_tuple = db.execute(query).fetchone()
    folder_dict = folder_tuple_to_folder_dict(folder_tuple)
    return folder_dict


def get_folder_access(db: sqlite3.Connection, folder_id: int, username: str) -> dict:
    query = f"SELECT * FROM folders_access WHERE folder_id={folder_id} and username='{username}' "
    folder_access_tuple = db.execute(query).fetchone()
    folder_access_dict = {
        'id': folder_access_tuple[0],
        'username': folder_access_tuple[1],
        'owner': folder_access_tuple[2],
        'rw': folder_access_tuple[3],
    } if folder_access_tuple is not None else None
    return folder_access_dict


def git_file_by_name_and_folder_id(db: sqlite3.Connection, name: str, folder_id: int) -> dict:
    query = f"SELECT * FROM files WHERE name='{name}' and folder_id={folder_id}"
    file_tuple = db.execute(query).fetchone()
    file_dict = {
        'id': file_tuple[0],
        'name': file_tuple[1],
        'folder_id': file_tuple[2],
        'read_token': file_tuple[3],
        'write_token': file_tuple[4],
    } if file_tuple is not None else None
    return file_dict


def get_file_access(db: sqlite3.Connection, file_id: int, username: str) -> dict:
    query = f"SELECT * FROM files_access WHERE file_id={file_id} and username='{username}'"
    file_access_folder = db.execute(query).fetchone()
    file_access_dict = {
        'file_id': file_access_folder[0],
        'username': file_access_folder[1],
        'owner': file_access_folder[2],
        'rw': file_access_folder[3],
    }
    return file_access_dict


def insert_into_folders(db: sqlite3.Connection, name: str, parent_id: int, base: str,
                        read_token: str = None, write_token: str = None, timestamp: int = None):
    if timestamp is None:
        timestamp = get_timestamp()
    if read_token is None:
        read_token = gen_nonce()
    if write_token is None:
        write_token = gen_nonce()
    query = f"""INSERT INTO folders (name, parent_id, read_token, write_token, timestamp, base)
            VALUES ("{name}", {parent_id}, "{read_token}", "{write_token}",
            {timestamp}, {base})"""
    insert_update_query(db, query)


def insert_into_accounts(db: sqlite3.Connection, username: str, first_name: str, last_name: str,
                         password: str, base_folder_id: int, public_key: rsa.PublicKey,
                         host: str, ip: str):
    query = f"""INSERT INTO accounts (username, first_name, last_name, password, base_folder, 
                    public_key, host, ip) 
                VALUES ('{username}', '{first_name}', '{last_name}', '{password}', {base_folder_id},
                '{public_key}', '{host}', '{ip}')"""
    insert_update_query(db, query)


def insert_into_folders_acess(db: sqlite3.Connection, folder_id: int, username: str, owner: str, rw: str):
    query = f"""INSERT INTO folders_access (folder_id, username, owner, rw)
            VALUES ({folder_id}, "{username}", {owner}, {rw})"""
    insert_update_query(db, query)


def update_user(db: sqlite3.Connection, username: str,
                public_key: rsa.PublicKey, host: str, ip: str) -> None:
    query = f"""UPDATE accounts
            SET public_key="{public_key}", host="{host}", ip="{ip}"
             WHERE username="{username}" """
    insert_update_query(db, query)


def insert_update_query(db, query):
    db.execute(query)
    db.commit()
