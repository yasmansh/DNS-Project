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
        'port': user_tuple[7],
    } if user_tuple is not None else None
    return user_dict


def convert_folder_tuple_to_folder_dict(folder_tuple: tuple) -> dict:
    folder_dict = {
        'id': folder_tuple[0],
        'name': folder_tuple[1],
        'parent_id': folder_tuple[2],
        'timestamp': folder_tuple[3],
        'is_base': folder_tuple[4],
    } if folder_tuple is not None else None
    return folder_dict


def get_folder_by_id(db: sqlite3.Connection, folder_id: int):
    folder_query = f'={folder_id}' if folder_id is not None else ' IS NULL'
    query = f"SELECT * FROM folders WHERE id{folder_query}"
    folder_tuple = db.execute(query).fetchone()
    folder_dict = convert_folder_tuple_to_folder_dict(folder_tuple)
    return folder_dict


def get_folder_by_name_and_parent(db: sqlite3.Connection, name: str, parent_id: int):
    parent_query = f'parent_id={parent_id}' if parent_id is not None else 'parent_id IS NULL'
    query = f'SELECT * FROM folders WHERE name="{name}" and {parent_query}'
    folder_tuple = db.execute(query).fetchone()
    folder_dict = convert_folder_tuple_to_folder_dict(folder_tuple)
    return folder_dict


def convert_file_tuple_to_file_dict(file_tuple):
    file_dict = {
        'id': file_tuple[0],
        'name': file_tuple[1],
        'folder_id': file_tuple[2],
        'read_token': file_tuple[3],
        'write_token': file_tuple[4],
    } if file_tuple is not None else None
    return file_dict


def get_file_by_name_and_folder_id(db: sqlite3.Connection, name: str, folder_id: int) -> dict:
    query = f"SELECT * FROM files WHERE name='{name}' and folder_id={folder_id}"
    file_tuple = db.execute(query).fetchone()
    file_dict = convert_file_tuple_to_file_dict(file_tuple)
    return file_dict


def get_file_by_id(db: sqlite3.Connection, file_id: int) -> dict:
    query = f'SELECT * FROM files WHERE id="{file_id}"'
    file_tuple = db.execute(query).fetchone()
    file_dict = convert_file_tuple_to_file_dict(file_tuple)
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


def insert_into_folders(db: sqlite3.Connection, name: str, base: str,
                        parent_id: int = None, timestamp: int = None):
    if parent_id is None:
        parent_id = "null"
    if timestamp is None:
        timestamp = get_timestamp()
    query = f"""INSERT INTO folders (name, parent_id, timestamp, base)
            VALUES ("{name}", {parent_id}, {timestamp}, {base})"""
    insert_update_delete_query(db, query)


def insert_into_accounts(db: sqlite3.Connection, username: str, first_name: str, last_name: str,
                         password: str, base_folder_id: int, public_key: rsa.PublicKey,
                         host: str, port: str) -> None:
    query = f"""INSERT INTO accounts (username, first_name, last_name, password, base_folder, 
                    public_key, host, port) 
                VALUES ('{username}', '{first_name}', '{last_name}', '{password}', {base_folder_id},
                '{public_key}', '{host}', '{port}')"""
    insert_update_delete_query(db, query)


def insert_into_files(db: sqlite3.Connection, file_name: str, folder_id: int,
                      read_token: str, write_token: str) -> None:
    query = f"""INSERT INTO files (name, folder_id, read_token, write_token)
        VALUES ('{file_name}', {folder_id}, '{read_token}', '{write_token}')"""
    insert_update_delete_query(db, query)


def insert_into_files_access(db: sqlite3.Connection, file_id: int, username: str, owner: str, rw: str) -> None:
    query = f"""INSERT INTO files_access (file_id, username, owner, rw)
        VALUES ({file_id}, '{username}', {owner}, {rw})"""
    insert_update_delete_query(db, query)


def update_user(db: sqlite3.Connection, username: str,
                public_key: rsa.PublicKey, host: str, port: str) -> None:
    query = f"""UPDATE accounts
            SET public_key="{public_key}", host="{host}", port="{port}"
             WHERE username="{username}" """
    insert_update_delete_query(db, query)


def update_folder_timestamp(db: sqlite3.Connection, folder_id: int, timestamp: int) -> None:
    query = f"""UPDATE folders
        set timestamp={timestamp}
        WHERE id={folder_id}"""
    insert_update_delete_query(db, query)


def update_file_parent_folder(db: sqlite3.Connection, file_name: str,
                              old_parent_id: int, new_parent_id: int):
    query = f"""UPDATE files
    set folder_id={new_parent_id}
    WHERE name="{file_name}" and folder_id={old_parent_id}"""
    insert_update_delete_query(db, query)


def update_folder_parent_id(db: sqlite3.Connection, folder_id: int, new_parent_id: int) -> None:
    query = f"""UPDATE folders
            set parent_id={new_parent_id}
            WHERE id={folder_id}"""
    insert_update_delete_query(db, query)


def delete_file_from_database(db: sqlite3.Connection, file_name: str, folder_id: int):
    query = f'DELETE from files WHERE name="{file_name}" and folder_id={folder_id}'
    insert_update_delete_query(db, query)


def delete_folder_from_database(db: sqlite3.Connection, folder_id: int):
    query = f'DELETE FROM folders WHERE id={folder_id}'
    insert_update_delete_query(db, query)


def insert_update_delete_query(db, query):
    db.execute(query)
    db.commit()
