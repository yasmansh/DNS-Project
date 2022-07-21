import sqlite3
import os
from utils import get_timestamp, gen_nonce
from db_utils import insert_update_query
from meta_utils import write_meta
import rsa

db = sqlite3.connect('server.db')

db.execute("""CREATE TABLE folders
                (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, parent_id int,
                 timestamp BIGINT, base BOOLEAN,
                FOREIGN KEY (parent_id) REFERENCES folders(id))
                """)

db.execute("""CREATE TABLE files
                (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, folder_id int,
                read_token char(64), write_token char(64),
                FOREIGN KEY (folder_id) REFERENCES folders(id))
                """)

db.execute("""CREATE TABLE files_access
                (file_id int, username varchar(32), owner BOOLEAN, rw BOOLEAN,
                FOREIGN KEY (file_id) REFERENCES folders(id))
                """)

db.execute("""CREATE TABLE accounts
                (username varchar(32) primary key, first_name varchar(32), last_name varchar(32),
                 password char(64), base_folder int,
                 public_key varchar(700), host char(20), port char(20),
                 FOREIGN KEY (base_folder) REFERENCES folders(id))
                """)


db.execute("""CREATE TABLE receivers
                (user_port char(20) PRIMARY KEY, receiver_port char(20))""")


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
query = f"""INSERT INTO folders (id, name, parent_id, timestamp, base)
VALUES (1, 'Directory', 1, {ts}, false)"""
insert_update_query(db, query)
content = f"""1
{ts}
0"""
write_meta(os.path.join(os.getcwd(), 'Directory'), content, public_key)
