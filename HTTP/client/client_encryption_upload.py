import base64
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket

# 定义服务器地址和端口
HOST = 'localhost'
PORT = 8080

# 定义用户名和密码
USERNAME = b'client1'
PASSWORD = b'123'

# 创建套接字
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 连接服务器
client_socket.connect((HOST, PORT))
print(f'Connected to server {HOST}:{PORT}\n\n')

# 接收并打印服务器的响应
# response = client_socket.recv(1024).__bytes__()
# Step 1: Receive the public key from the server
server_public_key_bytes = client_socket.recv(1024)
server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())

# Step 2: Generate a symmetric key for communication
symmetric_key = os.urandom(16)  # In a real-world scenario, use a secure key exchange algorithm
iv = bytes(16)
# Encrypt the symmetric key with the server's public key
encrypted_key = server_public_key.encrypt(
    symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

client_socket.sendall(encrypted_key)

# 构建HTTP请求--upload
request2 = b'POST /upload?path=client1/ HTTP/1.1\r\n'
request2 += b'Host: localhost:8080\r\n'
request2 += b'Authorization: Basic ' + base64.b64encode(USERNAME + b':' + PASSWORD).decode().encode() + b'\r\n'
request2 += b'Content-Length: 159\r\n'
request2 += b'Content-Type: multipart/form-data; boundary=72a23f646f21506a7335f47de4ac385f\r\n'
request2 += b'\r\n\r\n'
request2 += b'--72a23f646f21506a7335f47de4ac385f\r\n'
request2 += b'Content-Disposition: form-data; name="firstFile"; filename="a.txt"\r\n'
request2 += b'\r\n'
request2 += b'sadfsdfaaaa\r\n'
request2 += b'--72a23f646f21506a7335f47de4ac385f--\r\n'
cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB8(iv), backend=default_backend())
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()
encrypted_data = encryptor.update(request2)
client_socket.sendall(encrypted_data)
print(f"Test post--upload to Server: \n{request2.decode()}")
response = client_socket.recv(1024)
decrypted_data = decryptor.update(response)
print(f"Test post from Server: {decrypted_data.decode()}\n\n")

# 构建HTTP请求--upload
request2 = b'POST /upload?path=client1/ HTTP/1.1\r\n'
request2 += b'Host: localhost:8080\r\n'
request2 += b'Authorization: Basic Y2xpZW50MToxMjM=\r\n'
request2 += b'Content-Length: 159\r\n'
request2 += b'Content-Type: multipart/form-data; boundary=72a23f646f21506a7335f47de4ac385f\r\n'
request2 += b'\r\n\r\n'
request2 += b'--72a23f646f21506a7335f47de4ac385f\r\n'
request2 += b'Content-Disposition: form-data; name="firstFile"; filename="b.txt"\r\n'
request2 += b'\r\n'
request2 += b'sadasdfaaaa\r\n'
request2 += b'--72a23f646f21506a7335f47de4ac385f--\r\n'
encrypted_data = encryptor.update(request2)
client_socket.sendall(encrypted_data)
print(f"Test post--upload to Server: \n{request2.decode()}")
response = client_socket.recv(1024)
decrypted_data = decryptor.update(response)
print(f"Test post from Server:: {decrypted_data.decode()}")

# 构建HTTP请求--upload
request2 = b'POST /upload?path=client1/ HTTP/1.1\r\n'
request2 += b'Host: localhost:8080\r\n'
request2 += b'Authorization: Basic Y2xpZW50MToxMjM=\r\n'
request2 += b'Content-Length: 157\r\n'
request2 += b'Content-Type: multipart/form-data; boundary=72a23f646f21506a7335f47de4ac385f\r\n'
request2 += b'\r\n\r\n'
request2 += b'--72a23f646f21506a7335f47de4ac385f\r\n'
request2 += b'Content-Disposition: form-data; name="firstFile"; filename="b.txt"\r\n'
request2 += b'\r\n'
request2 += b'sadasdfaaaa\r\n'
request2 += b'--72a23f646f21506a7335f47de4ac385f--\r\n'
encrypted_data = encryptor.update(request2)
client_socket.sendall(encrypted_data)
print(f"Test post--upload to Server: \n{request2.decode()}")
response = client_socket.recv(1024)
decrypted_data = decryptor.update(response)
print(f"Test post from Server:: {decrypted_data.decode()}")