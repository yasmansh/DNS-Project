import datetime
import string
import random
import rsa
import hashlib
import os


def get_timestamp():
    ct = datetime.datetime.now()  # current time
    ts = ct.timestamp()  # timestamp of current time
    return round(ts)


def check_freshness(timestamp):
    if get_timestamp() - float(timestamp) <= 10:  # Protection against repeated attacks
        return True
    return False


def random_string(size):
    characters = string.ascii_letters
    characters += string.digits
    characters += string.punctuation
    return ''.join(random.choice(characters) for _ in range(size))


def encrypt_message(message, public_key):
    n = 53
    chunks = [message[i:i + n] for i in range(0, len(message), n)]
    chunks_cipher = [rsa.encrypt(i.encode(), public_key) for i in chunks]
    cipher = b''
    for chunk_cipher in chunks_cipher:
        cipher += chunk_cipher
    return cipher


def create_empty_dir(base_path, db, public_key):
    rand = random_string(30)
    name = hashlib.sha256(rand.encode()).hexdigest()
    path = os.path.join(base_path, name)
    nonce = hashlib.sha256(random_string(64).encode()).hexdigest()
    if not os.path.exists(path):
        os.mkdir(path)
        ts = get_timestamp()
        db.execute(f"""INSERT INTO dirs (name, parent_id, nonce, timestamp, empty)
            VALUES ("{name}", 1, "{nonce}", {ts}, true)""")
        db.commit()
        query = f"""SELECT * FROM dirs
        WHERE name="{name}" and parent_id=1
        """
        response = db.execute(query)
        folder = response.fetchone()
        folder_id = folder[0]
        f = open(os.path.join(path, '.meta'), 'ab')
        message = f"""{folder_id}
{ts}
0"""
        f.write(encrypt_message(message, public_key))
        f.close()


def decrypt_cipher(cipher, private_key):
    n = 64
    chunks = [cipher[i:i + n] for i in range(0, len(cipher), n)]
    chunks_plain = [rsa.decrypt(i, private_key).decode() for i in chunks]
    command = ''.join(chunks_plain)
    return command
