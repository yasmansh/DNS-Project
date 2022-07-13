import socket

host = ""
port = 0
with open("configuration_ip_port", "r") as f:
    host = f.readline().strip()
    port = int(f.readline().strip())
print("ip=" + str(host) + "\tport=" + str(port))

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))

response = client.recv(2048)
username = input(response.decode())
client.send(str.encode(username))

response = client.recv(2048)
password = input(response.decode())
client.send(str.encode(password))

response = client.recv(2048)
response = response.decode()
print(response)
''' Response : Status of Connection :
	1 : Registeration successful 
	2 : Login Successful
	3 : Login Failed
'''

client.close()
