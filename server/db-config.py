import hashlib
import sqlite3
import os
import random
import string
from utils import get_timestamp, random_string, encrypt_message, create_empty_dir
import rsa

db = sqlite3.connect('server.db')

db.execute("""CREATE TABLE dirs
                (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, parent_id int,
                 nonce char(64), timestamp BIGINT, empty BOOLEAN,
                FOREIGN KEY (parent_id) REFERENCES dirs(id))
                """)

db.execute("""CREATE TABLE dirs_access
                (dir_id int, username varchar(32), owner BOOLEAN, rw BOOLEAN,
                FOREIGN KEY (dir_id) REFERENCES dirs(id))
                """)

db.execute("""CREATE TABLE files
                (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, dir_id int,
                 nonce char(64), timestamp BIGINT,
                FOREIGN KEY (dir_id) REFERENCES dirs(id))
                """)

db.execute("""CREATE TABLE files_access
                (file_id int, username varchar(32), owner BOOLEAN, r BOOLEAN, rw BOOLEAN,
                FOREIGN KEY (file_id) REFERENCES files(id))
                """)

db.execute("""CREATE TABLE accounts
                (username varchar(32) primary key, first_name varchar(32), last_name varchar(32),
                 password char(64), public_key varchar(512), base_dir int,
                 FOREIGN KEY (base_dir) REFERENCES dirs(id))
                """)

public_key, private_key = rsa.newkeys(512)

with open("PU_server.pem", "wb") as f:
    pk = rsa.PublicKey.save_pkcs1(public_key)
    f.write(pk)

with open("PR_server.pem", "wb") as f:
    pk = rsa.PrivateKey.save_pkcs1(private_key)
    f.write(pk)


nonce = hashlib.sha256(random_string(64).encode()).hexdigest()
ts = get_timestamp()
db.execute(f"""INSERT INTO dirs (name, parent_id, nonce, timestamp, empty)
VALUES ('Directory', null, "{nonce}", {ts}, false)""")
db.commit()
base_path = os.path.join(os.getcwd(), 'Directory')
f = open(os.path.join(base_path, '.meta'), 'ab')
ts = get_timestamp()
message = f"""1
{ts}
0"""
f.write(encrypt_message(message, public_key))
f.close()
for i in range(200):
    create_empty_dir(base_path, db, public_key)
