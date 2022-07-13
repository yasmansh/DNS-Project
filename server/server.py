import socket
import threading
import hashlib
import rsa
import datetime


def get_timestamp():
    ct = datetime.datetime.now()  # current time
    ts = ct.timestamp()  # timestamp of current time
    return ts


"""
ct = datetime.datetime.now()    # current time
ts = ct.timestamp() # timestamp of current time
print("timestamp:", ts)
"""

public_key, private_key = rsa.newkeys(512)
f = open("server_pub_key.txt", "a")  # append mode
f.write(str(public_key))
f.close()

host = ""
port = 0
with open("..\client\configuration_ip_port", "r") as f:
    host = f.readline().strip()
    port = int(f.readline().strip())
# print("ip=" + str(host) + "\tport=" + str(port))

server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)

try:
    server_socket.bind((host, port))
except socket.error as e:
    print(str(e))

print('Waiting for a connection...')
server_socket.listen(20)
user_pass = {}
user_info = []  # (username, first_name, last_name)


def threaded_client(client):  # Authentication
    while True:
        client.send(str.encode('1. Sign Up\n2. Login\n3. Exit'))
        command = client.recv(2048).decode()
        if check_freshness(command):
            command = command[:str(command).index('$')]
        else:
            client.send(str.encode('Please try again later.\n|'))
            continue

        if command == '1':
            client.send(str.encode('Please enter your first name: '))
            command = client.recv(2048).decode()
            if check_freshness(command):
                first_name = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue
            client.send(str.encode('Please enter your last name: '))
            command = client.recv(2048).decode()
            if check_freshness(command):
                last_name = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue
            client.send(str.encode('Please enter your username: '))
            command = client.recv(2048).decode()
            if check_freshness(command):
                username = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue
            while username == 'root' or username in user_pass:
                client.send(str.encode('This username is already existed. Please enter another one: '))
                command = client.recv(2048).decode()
                if check_freshness(command):
                    username = command[:str(command).index('$')]
                else:
                    client.send(str.encode('Please try again later.\n|'))
                    continue  ###

            client.send(str.encode('Please enter your password: '))
            command = client.recv(2048).decode()
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
            command = client.recv(2048).decode()
            if check_freshness(command):
                username = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue
            client.send(str.encode('Please enter your password: '))
            command = client.recv(2048).decode()
            if check_freshness(command):
                password = command[:str(command).index('$')]
            else:
                client.send(str.encode('Please try again later.\n|'))
                continue
            password = hashlib.sha256(str.encode(password)).hexdigest()
            if (username in user_pass and user_pass[username] == password):
                client.send(str.encode('Login successful|'))
                print('Connected : ', username)
            else:
                client.send(str.encode('Incorrect username or password.|\n'))
                continue  # Back to menu

        elif command == '3':
            print('client disconnected.|')
            break
        else:
            print("Not understand|")
    client.close()


def check_freshness(command):
    ts = str(command)[str(command).index('$') + 1:]
    if (get_timestamp() - float(ts)) <= 10:  # Protection against repeated attacks
        return True
    return False


while True:
    Client, address = server_socket.accept()
    client_handler = threading.Thread(
        target=threaded_client,
        args=(Client,)
    )
    client_handler.start()
ServerSocket.close()