# client1.py

import socket

# 定义服务器地址和端口
HOST = 'localhost'
PORT = 8080

# 创建套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

# 发送HTTP请求获取文件
range_header = 'Authorization: Basic Y2xpZW50MToxMjM=\r\n'
request = 'GET /test.txt HTTP/1.1\r\nHost: {}\r\n{}\r\n'.format(HOST, range_header)
sock.sendall(request.encode())

# 接收响应并模拟中断（读取一部分数据后断开连接）
response = b''
try:
    while True:
        data = sock.recv(512)  # 假设我们只读取512字节然后中断
        if not data:
            break
        response += data
        if len(response) >= 512:  # 到达假定的中断点
            break
finally:
    sock.close()

print('First response (partial):')
print(response.decode())

# 从中断点继续请求的起始字节
interrupted_at = len(response)

# 创建新的套接字进行续传
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

# 发送带有Range头的HTTP请求，从中断的下一个字节开始请求
range_header = 'Range: bytes={}-\r\nAuthorization: Basic Y2xpZW50MToxMjM=\r\n'.format(interrupted_at)
request = 'GET /test.txt HTTP/1.1\r\nHost: {}\r\n{}\r\n'.format(HOST, range_header)
sock.sendall(request.encode())

# 接收剩余部分的响应
remaining_response = b''
data = sock.recv(1024)  # 读取第一部分数据
remaining_response += data
# while True:
#     data = sock.recv(1024)  # 继续读取剩余数据
#     if not data:
#         break
#     remaining_response += data

print('Second response (remaining):')
print(remaining_response.decode())

# 关闭连接
sock.close()