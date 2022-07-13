import socket
import datetime
import rsa


def get_timestamp():
    ct = datetime.datetime.now()  # current time
    ts = ct.timestamp()  # timestamp of current time
    return ts


host = ""
port = 0
with open("configuration_ip_port", "r") as f:
    host = f.readline().strip()
    port = int(f.readline().strip())

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))

with open("..\server\PK_server.pem", "rb") as f:
    data = f.read()
    server_public_key = rsa.PublicKey.load_pkcs1(data)

while True:
    try:
        response = client.recv(2048).decode()
        if response[-1] == '|':
            print(response[:-1])
            continue
        print(response)
        command = input()
        command = command + '$' + str(get_timestamp())
        cipher = rsa.encrypt(command.encode(), server_public_key)
        client.send(cipher)

    except Exception as e:
        print("Error")
        break
client.close()
