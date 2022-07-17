import sqlite3
import rsa


db = sqlite3.connect('client.db')

db.execute("""CREATE TABLE file_keys
                (id int, public_key varchar(512), private_key varchar(512), 
                ticket char(64))
                """)

db.execute("""CREATE TABLE dir_keys
            (id int, ticket char(64))""")

public_key, private_key = rsa.newkeys(512)
with open("PU_client.pem", "wb") as f:
    pk = rsa.PublicKey.save_pkcs1(public_key)
    f.write(pk)

with open("PR_client.pem", "wb") as f:
    pk = rsa.PrivateKey.save_pkcs1(private_key)
    f.write(pk)
