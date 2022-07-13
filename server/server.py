import socket
import threading
import hashlib

host = ""
port = 0
with open("..\client\configuration_ip_port", "r") as f:
    host = f.readline().strip()
    port = int(f.readline().strip())
print("ip=" + str(host) + "\tport=" + str(port))

server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
num_of_connection = 0
try:
    server_socket.bind((host, port))
except socket.error as e:
    print(str(e))

print('Waitiing for a connection...')
server_socket.listen(5)
user_pass = {}


def threaded_client(connection):  # Authentication
    connection.send(str.encode('Please enter your username: '))
    username = connection.recv(2048)
    username = username.decode()
    connection.send(str.encode('Please enter your password: '))
    password = connection.recv(2048)
    password = password.decode()

    password = hashlib.sha256(str.encode(password)).hexdigest()  # Password hash using SHA256
    if username not in user_pass:  # Registeration
        user_pass[username] = password
        connection.send(str.encode('Registeration Successful'))
    else:  # Login
        if (user_pass[username] == password):
            connection.send(str.encode('Login Successful'))
            print('Connected : ', username)
        else:
            connection.send(str.encode('Login Failed'))
            print('Connection denied : ', username)
    while True:
        break
    connection.close()


while True:
    Client, address = server_socket.accept()
    client_handler = threading.Thread(
        target=threaded_client,
        args=(Client,)
    )
    client_handler.start()
    num_of_connection += 1
    print('Connection Request: ' + str(num_of_connection))
ServerSocket.close()
