import sqlite3

import rsa
from rsa import PublicKey, PrivateKey


def select_from_file_keys(db: sqlite3.Connection, file_id: int):
    query = f"SELECT * FROM file_keys WHERE id={file_id}"
    file_tuple = db.execute(query).fetchone()
    file_dict = {
        'file_id': file_tuple[0],
        'public_key': eval(file_tuple[1]),
        'private_key': eval(file_tuple[2]),
        'ticket': file_tuple[3],
    } if file_tuple is not None else None
    return file_dict


def insert_into_file_keys(db: sqlite3.Connection, file_id, token):
    public_key, private_key = rsa.newkeys(512)
    query = f"""INSERT INTO file_keys (id, public_key, private_key, token)
            VALUES ({file_id}, '{public_key}', '{private_key}', '{token}')"""
    db.execute(query)
    db.commit()


def update_token(db: sqlite3.Connection, file_id, new_token):
    query = f"""UPDATE file_keys
                        SET token='{new_token}'
                        WHERE id={file_id}"""
    db.execute(query)
    db.commit()