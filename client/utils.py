import datetime
import string
import random
import rsa
import hashlib
import socket
import os


def get_timestamp() -> int:
    """

    :rtype: object
    """
    ct = datetime.datetime.now()  # current time
    ts = ct.timestamp()  # timestamp of current time
    return round(ts)


def check_freshness(timestamp: int) -> bool:
    if get_timestamp() - float(timestamp) <= 10:  # Protection against repeated attacks
        return True
    return False


def random_string(size: int) -> str:
    characters = string.ascii_letters
    characters += string.digits
    characters += string.punctuation
    return ''.join(random.choice(characters) for _ in range(size))


def encrypt_message(message: str, public_key: rsa.PublicKey):
    n = 53
    chunks = [message[i:i + n] for i in range(0, len(message), n)]
    chunks_cipher = [rsa.encrypt(i.encode(), public_key) for i in chunks]
    cipher = b''
    for chunk_cipher in chunks_cipher:
        cipher += chunk_cipher
    return cipher


def decrypt_cipher(cipher: bytes, private_key: rsa.PrivateKey) -> str:
    n = 64
    chunks = [cipher[i:i + n] for i in range(0, len(cipher), n)]
    chunks_plain = [rsa.decrypt(i, private_key).decode() for i in chunks]
    command = ''.join(chunks_plain)
    return command


def encrypt_and_sign(message: str, private_key: rsa.PrivateKey, public_key: rsa.PublicKey) -> bytes:
    timestamp = get_timestamp()
    plaintext = f"{message}||{timestamp}"
    signature = rsa.sign(plaintext.encode(), private_key, 'SHA-256')
    cipher = encrypt_message(f"{plaintext}||{signature}", public_key)
    return cipher


def check_sign_and_timestamp(client: socket.socket, cipher: str, private_key: rsa.PrivateKey,
                             public_key: rsa.PublicKey) -> object:
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


def gen_nonce() -> str:
    return hashlib.sha256(random_string(64).encode()).hexdigest()


def hash_file(filename: str) -> str:
    h = hashlib.sha256()
    with open(filename, 'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h.update(chunk)

    return h.hexdigest()


def send_message(client: socket.socket, message: str, user_public_key: rsa.PublicKey,
                 private_key: rsa.PrivateKey) -> None:
    """

    :rtype: None
    """
    cipher = encrypt_and_sign(message, private_key, user_public_key)
    client.send(cipher)


def get_message(client: socket.socket, user_public_key: rsa.PublicKey, private_key: rsa.PrivateKey):
    cipher = client.recv(2048)
    ok, cmd_split = check_sign_and_timestamp(client, cipher, private_key, user_public_key)
    return ok, cmd_split
