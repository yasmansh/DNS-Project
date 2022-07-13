import socket
import threading
import hashlib
import rsa
import datetime
import pyDH


def get_timestamp():
    ct = datetime.datetime.now()  # current time
    ts = ct.timestamp()  # timestamp of current time
    return ts


def check_freshness(command):
    ts = str(command)[str(command).index('$') + 1:]
    if (get_timestamp() - float(ts)) <= 10:  # Protection against repeated attacks
        return True
    return False


def secure_file_system(client):
    pass


def threaded_client(client):  # Authentication
    while True:
        client.send(str.encode('1. Sign Up\n2. Login\n3. Exit'))
        command = rsa.decrypt(client.recv(2048), private_key).decode()
        if check_freshness(command):
            command = command[:str(command).index('$')]
        else:
            client.send(str.encode('Please try again later.\n|'))
            continue

        if command == '1':
            client.send(str.encode('Please enter your first name: '))
            command = rsa.decrypt(client.recv(2048), private_key).decode()
            if check_freshness(command):
                first_name = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue
            client.send(str.encode('Please enter your last name: '))
            command = rsa.decrypt(client.recv(2048), private_key).decode()
            if check_freshness(command):
                last_name = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue
            client.send(str.encode('Please enter your username: '))
            command = rsa.decrypt(client.recv(2048), private_key).decode()
            if check_freshness(command):
                username = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue
            while username == 'root' or username in user_pass:
                client.send(str.encode('This username is already existed. Please enter another one: '))
                command = rsa.decrypt(client.recv(2048), private_key).decode()
                if check_freshness(command):
                    username = command[:str(command).index('$')]
                else:
                    client.send(str.encode('Please try again later.\n|'))
                    continue  ###

            client.send(str.encode('Please enter your password: '))
            command = rsa.decrypt(client.recv(2048), private_key).decode()
            if check_freshness(command):
                password = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue

            # Password hash using SHA256
            password = hashlib.sha256(str.encode(password)).hexdigest()
            user_pass[username] = password
            user_info.append((username, first_name, last_name))
            client.send(str.encode('Registration successful|'))
            continue  # Back to menu

        elif command == '2':
            client.send(str.encode('Please enter your username: '))
            command = rsa.decrypt(client.recv(2048), private_key).decode()
            if check_freshness(command):
                username = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue
            client.send(str.encode('Please enter your password: '))
            command = rsa.decrypt(client.recv(2048), private_key).decode()
            if check_freshness(command):
                password = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue
            password = hashlib.sha256(str.encode(password)).hexdigest()
            if (username in user_pass and user_pass[username] == password):
                client.send(str.encode('Login successful|'))
                print('Connected : ', username)
                secure_file_system(client)
            else:
                client.send(str.encode('Incorrect username or password.|\n'))
                continue  # Back to menu

        elif command == '3':
            print('client disconnected.|')
            break
        else:
            print("Not understand|")
    client.close()


public_key, private_key = rsa.newkeys(512)

with open("PK_server.pem", "wb") as f:
    pk = rsa.PublicKey.save_pkcs1(public_key)
    f.write(pk)

host = ""
port = 0
with open("..\client\configuration_ip_port", "r") as f:
    host = f.readline().strip()
    port = int(f.readline().strip())

server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)

try:
    server_socket.bind((host, port))
except socket.error as e:
    print(str(e))

print('Waiting for a connection...')
server_socket.listen(20)
user_pass = {}
user_info = []  # (username, first_name, last_name)

while True:
    Client, address = server_socket.accept()
    client_handler = threading.Thread(
        target=threaded_client,
        args=(Client,)
    )
    client_handler.start()
ServerSocket.close()
