import socket
import datetime


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

f = open("..\server\server_pub_key.txt", "r")
public_key_server = f.read()
f.close()

while True:
    try:
        response = client.recv(2048).decode()
        print(response)
        if response[-1] == '|':
            continue
        command = input()
        command = command + '$' + str(get_timestamp())
        client.send(str.encode(command))


    except Exception as e:
        print("Error")
        break
"""
response = client.recv(2048)
username = input(response.decode())
client.send(str.encode(username))

response = client.recv(2048)
password = input(response.decode())
client.send(str.encode(password))

response = client.recv(2048).decode()
print(response)
"""

''' Response : Status of Connection :
     > Registration successful 
	 > Login successful
	 > Incorrect username or password.
'''

client.close()
