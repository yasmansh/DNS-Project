import hashlib
import sqlite3
import os
import random
import string
from utils import get_timestamp, random_string, encrypt_message, gen_nonce, insert_query, write_meta
import rsa

db = sqlite3.connect('server.db')

db.execute("""CREATE TABLE dirs
                (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, parent_id int,
                 read_token char(64), write_token char(64), timestamp BIGINT, base BOOLEAN,
                FOREIGN KEY (parent_id) REFERENCES dirs(id))
                """)

db.execute("""CREATE TABLE dirs_access
                (dir_id int, username varchar(32), owner BOOLEAN, rw BOOLEAN,
                FOREIGN KEY (dir_id) REFERENCES dirs(id))
                """)

db.execute("""CREATE TABLE files
                (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, dir_id int,
                read_token char(64), write_token char(64), timestamp BIGINT,
                FOREIGN KEY (dir_id) REFERENCES dirs(id))
                """)

db.execute("""CREATE TABLE files_access
                (file_id int, username varchar(32), owner BOOLEAN, r BOOLEAN, rw BOOLEAN,
                FOREIGN KEY (file_id) REFERENCES files(id))
                """)

db.execute("""CREATE TABLE accounts
                (username varchar(32) primary key, first_name varchar(32), last_name varchar(32),
                 password char(64), base_dir int,
                 FOREIGN KEY (base_dir) REFERENCES dirs(id))
                """)

public_key, private_key = rsa.newkeys(512)

with open("PU_server.pem", "ab") as f:
    pk = rsa.PublicKey.save_pkcs1(public_key)
    f.write(pk)

with open("PR_server.pem", "ab") as f:
    pk = rsa.PrivateKey.save_pkcs1(private_key)
    f.write(pk)


read_token = gen_nonce()
write_token = gen_nonce()
ts = get_timestamp()
query = f"""INSERT INTO dirs (id, name, parent_id, read_token, write_token, timestamp, base)
VALUES (1, 'Directory', 1, "{read_token}", "{write_token}", {ts}, false)"""
insert_query(db, query)
content = f"""1
{ts}
0"""
write_meta(os.path.join(os.getcwd(), 'Directory'), content, public_key)
