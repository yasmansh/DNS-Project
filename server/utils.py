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


def decrypt_cipher(cipher, private_key):
    n = 64
    chunks = [cipher[i:i + n] for i in range(0, len(cipher), n)]
    chunks_plain = [rsa.decrypt(i, private_key).decode() for i in chunks]
    command = ''.join(chunks_plain)
    return command


def encrypt_and_sign(message, private_key, public_key):
    timestamp = get_timestamp()
    plaintext = f"{message}||{timestamp}"
    signature = rsa.sign(plaintext.encode(), private_key, 'SHA-256')
    cipher = encrypt_message(f"{plaintext}||{signature}", public_key)
    return cipher


def check_sign_and_timestamp(cipher, private_key, public_key, client):
    plaintext = decrypt_cipher(cipher, private_key)
    plaintext = plaintext.split('||')
    message = '||'.join(plaintext[:-2])
    timestamp = eval(plaintext[-2])
    signature = eval(plaintext[-1])
    m = '||'.join(plaintext[:-1])
    if not rsa.verify(str.encode(m), signature, public_key):
        message = f"M||Wrong Signature!"
        client.send(encrypt_and_sign(message, private_key, public_key))
        return False, ""
    if not check_freshness(timestamp):
        message = f"M||Time Expired!"
        client.send(encrypt_and_sign(message, private_key, public_key))
        return False, ""
    return True, message.split("||")


def insert_query(db, query):
    db.execute(query)
    db.commit()


def gen_nonce():
    return hashlib.sha256(random_string(64).encode()).hexdigest()


def write_meta(path, content, public_key):
    f = open(os.path.join(path, '.meta'), 'wb')
    f.write(encrypt_message(content, public_key))
    f.close()