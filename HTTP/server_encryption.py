import argparse
import base64
from datetime import datetime, timedelta
import mimetypes
import re
import socket
import threading
import os
import json
import uuid
import select
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 从命令行参数中获取IP地址和端口号


parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ip', type=str, help='Specify the IP address')
parser.add_argument('-p', '--port', type=int, help='Specify the port number')
args = parser.parse_args()

# 如果没有指定IP地址和端口号，则使用默认值
HOST = args.ip if args.ip else 'localhost'
PORT = args.port if args.port else 8080

# 定义HTTP响应状态码
STATUS_OK = '200 OK'
STATUS_BAD_REQUEST = '400 Bad Request'
STATUS_UNAUTHORIZED = '401 Unauthorized'
STATUS_FORBIDDEN = '403 Forbidden'
STATUS_NOT_FOUND = '404 Not Found'
STATUS_METHOD_NOT_ALLOWED = '405 Method Not Allowed'
STATUS_PARTIAL_CONTENT = '206 Partial Content'
STATUS_RANGE_NOT_SATISFIABLE = '416 Range Not Satisfiable'
# 定义授权用户
AUTHORIZED_USERS = {'admin': 'password', 'client1': '123', 'client2': '123', 'client3': '123'}

# 定义文件存储路径（绝对路径）
# HEAD_PATH = r'C:/Code/CS305_Project/HTTP/data'
# 定义文件存储路径（相对路径）
HEAD_PATH = r'./data'


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key


# 定义HTTP服务器类
class HTTPServer:
    def __init__(self, host, port):
        # 定义服务器IP地址和端口号
        self.host = host
        self.port = port
        # 定义服务器套接字
        self.server_socket = None
        # 定义服务器运行状态
        self.server_running = True
        # 定义用户账户密码信息登入信息
        self.users_account = {}
        # 定义是否开启认证
        self.auth = 1
        # 维护一个字典来存储会话（session_id: username）
        self.sessions = {}
        # 账号密码或者会话ID
        self.if_cookie = 0

    # 启动服务器
    def start(self):
        try:
            self.setup_server_socket()
            self.listen_for_connections()
        except KeyboardInterrupt:
            self.server_running = False
            print('Server is shutting down.')

    # 设置服务器套接字
    def setup_server_socket(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f'Server is listening on {self.host}:{self.port}...')

    # 监听客户端连接
    def listen_for_connections(self):
        while self.server_running:
            client_socket, client_address = self.server_socket.accept()
            # client_socket.setblocking(False)
            print("+++++++++++++++++++++++++++++++++++++")
            print(f'Accepted connection from {client_address}')
            print("+++++++++++++++++++++++++++++++++++++")
            # 创建线程处理客户端请求
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_thread.start()

    def generateKey(self, client_socket, private_key, public_key):
        # Send public key to the client
        client_socket.sendall(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        # Receive encrypted symmetric key from the client
        encrypted_key = client_socket.recv(1024)
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Decrypted Symmetric Key: {decrypted_key.hex()}")
        iv = bytes(16)
        cipher = Cipher(algorithms.AES(decrypted_key), modes.CFB8(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        encryptor = cipher.encryptor()
        return decryptor, encryptor

    # 处理客户端请求
    def handle_client(self, client_socket, client_address):
        private_key, public_key = generate_key_pair()
        decryptor, encryptor = self.generateKey(client_socket, private_key, public_key)
        while True:
            print(f'Thread ID: {threading.current_thread().ident}')
            try:
                buffer_size = 1024  # 设置缓冲区大小
                received_data = b""  # 初始化接收的数据为一个空的 bytes 对象
                flag = 1
                readable = ''
                while readable or flag:
                    flag = 0
                    chunk = client_socket.recv(buffer_size)
                    received_data += chunk
                    readable, writable, exceptional = select.select([client_socket], [], [], 0)

                # 确保在退出循环后解码数据
                request = decryptor.update(received_data)
                # 将request分成两部分，一部分是request_line，一部分是request_body，注意可能有多个\r\n\r\n或者没有
                print(request)
                header, body = request.split(b'\r\n\r\n', 1)
                header = header.decode()
                # 看是不是post的upload方法，但先不能解码
                # if not request.startswith(b'POST /upload'):
                #     request = request.decode()
                #     match = re.search(r'filename="([^"]+)"'.encode(), request)
                #     filename = match.group(1).decode()
                #     file_type, _ = mimetypes.guess_type(filename)
                #     # 看是不是图片
                #     if file_type.startswith('image'):
                #         split_request = request.split(b'\r\n\r\n')
                #         union_request = split_request[0].decode() + "\r\n\r\n" + split_request[1].decode() + "\r\n\r\n" + split_request[2]
                #     else:
                #         union_request = request.decode()
                # else:
                #     union_request = request.decode()
                # request = union_request

                # check if the client is closed
                if request:
                    print(f'Request from {client_address}:')
                    print("-------------------------------------")
                    print(header)
                    print(body)
                    print("-------------------------------------")
                    set_cookie = ''
                    if self.auth == 1:
                        if_not_authorized, set_cookie = self.check_auth(header, body, client_socket)
                        if not if_not_authorized:
                            client_socket.close()
                            break
                    # 处理客户端请求
                    status, headers, response_body = self.handle_request(header, body)
                    if type(headers) == int:
                        headers = {
                            "Content-Type": "text/html",
                            "Content-Length": len(response_body),
                            "Connection": "keep-alive"
                        }
                    response = f'HTTP/1.1 {status}\r\n'
                    for key, value in headers.items():
                        response += f'{key}:{value}\r\n'
                    if set_cookie != '':
                        response += 'Set-Cookie: ' + set_cookie + '\r\n'
                    response += '\r\n'

                    if 'Connection: close' in header:
                        response_headers = response.split('\r\n\r\n')[0]
                        response_headers += '\r\nConnection: close\r\n\r\n'
                        response = response_headers + response.split('\r\n\r\n')[1]
                        response = encryptor.update(response.encode() + response_body)
                        client_socket.sendall(response)
                        client_socket.close()
                        break
                    else:
                        print(f'Response to {client_address}:')
                        print("-------------------------------------")
                        print(response)
                        print("-------------------------------------")
                        response = encryptor.update(response.encode() + response_body)
                        client_socket.sendall(response)
                else:
                    # 如果客户端关闭了连接，关闭套接字并退出线程
                    client_socket.close()
                    break

            except Exception as e:
                print(e)
                break

    # 权限检查
    def check_auth(self, header, body, client_socket):
        if 'Authorization' not in header and 'Cookie' not in header:
            response = f'HTTP/1.1 401 Unauthorized\r\n'
            response += 'WWW-Authenticate: Basic realm="Authorization Required"\r\n'
            response += '\r\n'

            client_socket.sendall(response.encode())
            return False, ''
        else:
            if 'Authorization' in header:
                request_lines = header.split('\r\n')
                auth_header = ''
                for line in request_lines:
                    if 'Authorization' in line:
                        auth_header = line.split(': ')[1]
                        break
                auth_type, auth_value = auth_header.split(' ')
                username, password = base64.b64decode(auth_value).decode().split(':')
                if username not in AUTHORIZED_USERS or AUTHORIZED_USERS[username] != password:
                    response = f'HTTP/1.1 401 Unauthorized\r\n'
                    response += 'WWW-Authenticate: Basic realm="Invalid Authorization"\r\n'
                    response += '\r\n'
                    client_socket.sendall(response.encode())
                    return False, ''
                else:
                    if 'Cookie' in header:
                        # 设置或读取会话Cookie
                        session_cookie = set_or_read_session_cookie(header)
                        # 如果已经存在会话Cookie，读取会话ID
                        session_id = session_cookie
                        # 检查会话ID的有效性
                        if session_id not in self.sessions:
                            # response = f'HTTP/1.1 401 Unauthorized\r\n'
                            # response += 'WWW-Authenticate: Basic realm="Invalid Authorization"\r\n'
                            # response += '\r\n'
                            # client_socket.sendall(response.encode())
                            # return False, ''
                            # 创建一个新的会话ID并更新
                            session_id = str(uuid.uuid4())
                            # 将会话ID存储在字典中
                            self.sessions[session_id] = username, datetime.now()
                            # 在响应中设置会话Cookie
                            set_cookie = f'session-id={session_id}; Expires={get_expiration_time()}'
                        else:
                            username_cookie, creation_time = self.sessions[session_id]
                            if username_cookie != username:
                                # response = f'HTTP/1.1 401 Unauthorized\r\n'
                                # response += 'WWW-Authenticate: Basic realm="Invalid Authorization"\r\n'
                                # response += '\r\n'
                                # client_socket.sendall(response.encode())
                                # return False, ''
                                # 创建一个新的会话ID并更新
                                session_id = str(uuid.uuid4())
                                # 将会话ID存储在字典中
                                self.sessions[session_id] = username, datetime.now()
                                # 在响应中设置会话Cookie
                                set_cookie = f'session-id={session_id}; Expires={get_expiration_time()}'
                            else:
                                expiration_time = creation_time + timedelta(minutes=30)  # 会话有效期为30分钟
                                if datetime.now() > expiration_time:
                                    # 会话过期，返回401 Unauthorized
                                    response = f'HTTP/1.1 401 Unauthorized\r\n'
                                    response += 'WWW-Authenticate: Basic realm="Invalid Authorization"\r\n'
                                    response += '\r\n'
                                    client_socket.sendall(response.encode())
                                    return False, ''
                                else:
                                    # 更新会话的最后访问时间
                                    self.sessions[session_id] = username, datetime.now()
                                    # 在响应中设置会话Cookie
                                    set_cookie = f'session-id={session_id}; Expires={get_expiration_time()}'
                    else:
                        # 如果没有会话Cookie，创建一个新的会话ID
                        session_id = str(uuid.uuid4())
                        # 将会话ID存储在字典中
                        self.sessions[session_id] = username, datetime.now()
                        # 在响应中设置会话Cookie
                        set_cookie = f'session-id={session_id}; Expires={get_expiration_time()}'
                    self.users_account[username] = True
                    print(f'User {username} authenticated successfully.')
                    return True, set_cookie
            elif 'Cookie' in header:
                # 设置或读取会话Cookie
                session_cookie = set_or_read_session_cookie(header)
                # 如果已经存在会话Cookie，读取会话ID
                session_id = session_cookie
                # 检查会话ID的有效性
                if session_id not in self.sessions:
                    response = f'HTTP/1.1 401 Unauthorized\r\n'
                    response += 'WWW-Authenticate: Basic realm="Invalid Authorization"\r\n'
                    response += '\r\n'
                    client_socket.sendall(response.encode())
                    return False, ''
                else:
                    username, creation_time = self.sessions[session_id]
                    expiration_time = creation_time + timedelta(minutes=30)  # 会话有效期为30分钟
                    if datetime.now() > expiration_time:
                        # 会话过期，返回401 Unauthorized
                        response = f'HTTP/1.1 401 Unauthorized\r\n'
                        response += 'WWW-Authenticate: Basic realm="Invalid Authorization"\r\n'
                        response += '\r\n'
                        client_socket.sendall(response.encode())
                        return False, ''
                    else:
                        # 更新会话的最后访问时间
                        self.sessions[session_id] = username, datetime.now()
                        self.users_account[username] = True
                        self.if_cookie = 1
                        print(f'User {username} authenticated successfully.')

                        # 在响应中设置会话Cookie
                        set_cookie = f'session-id={session_id}; Expires={get_expiration_time()}'
                return True, set_cookie

    # 处理客户端请求
    def handle_request(self, header, body):
        request_lines = header.split('\r\n')
        if len(request_lines) < 1:
            return STATUS_BAD_REQUEST, 400, 'Bad request'.encode()

        method, path, _ = request_lines[0].split(' ')

        if ('upload' in path or 'delete' in path) and method != 'POST':
            return STATUS_METHOD_NOT_ALLOWED, 405, 'Method Not Allowed'.encode()

        if method == "GET":
            # check request_line if contains Range
            for head in request_lines:
                if head.startswith('Range:'):
                    return self.handle_breakpoint_get_request(path, head)
            return self.handle_get_request(path)
        # sb
        elif method == 'HEAD':
            status, headers, _ = self.handle_get_request(path)
            return status, headers, ''.encode()
        elif method == 'POST':
            return self.handle_post_request(header, body, path)
        else:
            content = f'Unsupported method: {method}'
            return STATUS_METHOD_NOT_ALLOWED, 405, content.encode()

    # 处理GET请求
    def handle_get_request(self, path):
        if path == "/favicon.ico":
            content = "Favicon"
            return STATUS_OK, 200, content.encode()
        if '?' not in path:
            access_path = HEAD_PATH + path
            if os.path.isfile(access_path):
                filename = os.path.basename(access_path)
                with open(access_path, "rb") as file:
                    file_data = file.read()
                content_type, _ = mimetypes.guess_type(filename)
                content_length = len(file_data)
                headers = {
                    "Content-Type": content_type,
                    "Content-Length": content_length,
                    "Content-Disposition": f'inline; filename="{filename}"',
                    "Connection": "keep-alive"
                }
                return STATUS_OK, headers, file_data
            elif os.path.isdir(access_path):
                content = generate_html(access_path)
                return STATUS_OK, 200, content.encode()
            else:
                return STATUS_NOT_FOUND, 404, "File Not Found".encode()
        else:
            access_path = HEAD_PATH + path.split("?")[0]
            sustech_http = path.split("?")[1]
            if os.path.isfile(access_path):
                if sustech_http == "chunked=1":
                    filename = os.path.basename(access_path)
                    with open(access_path, "rb") as file:
                        file_data = file.read()
                    content_type, _ = mimetypes.guess_type(filename)
                    content_length = len(file_data)
                    # 使用 chunked 编码处理响应体
                    chunked_body = chunked_encoding(file_data)
                    headers = {
                        "Content-Type": content_type,
                        "Content-Length": content_length,
                        "Content-Disposition": f'attachment; filename="{filename}"',
                        "Transfer-Encoding": "chunked",
                        "Connection": "keep-alive"
                    }
                    return STATUS_OK, headers, chunked_body
                else:
                    filename = os.path.basename(access_path)
                    with open(access_path, "rb") as file:
                        file_data = file.read()
                    content_type, _ = mimetypes.guess_type(filename)
                    content_length = len(file_data)
                    headers = {
                        "Content-Type": content_type,
                        "Content-Length": content_length,
                        "Content-Disposition": f'attachment; filename="{filename}"',
                        "Connection": "keep-alive"
                    }
                    return STATUS_OK, headers, file_data
            elif os.path.isdir(access_path):
                if sustech_http == "SUSTech-HTTP=0":
                    content = generate_html(access_path)
                    return STATUS_OK, 200, content.encode()
                elif sustech_http == "SUSTech-HTTP=1":
                    files = os.listdir(access_path)
                    # 在每个文件夹名字后面加斜杠
                    files_with_slash = [f + '/' if os.path.isdir(os.path.join(access_path, f)) else f for f in files]
                    content = json.dumps(files_with_slash)
                    content_length = len(content)
                    content_type = "application/json"
                    headers = {
                        "Content-Type": content_type,
                        "Content-Length": content_length,
                        "Connection": "keep-alive"
                    }
                    return STATUS_OK, headers, content.encode()
                else:
                    return STATUS_METHOD_NOT_ALLOWED, 405, "Invalid SUSTech-HTTP parameter".encode()
            else:
                return STATUS_NOT_FOUND, 404, "File Not Found".encode()

    # 处理断点续传GET请求
    def handle_breakpoint_get_request(self, path, header):
        # Define file_size and file_path as required
        file_path = HEAD_PATH + path
        file_size = os.path.getsize(file_path)

        if not os.path.isfile(file_path):
            return None

        if path == "/favicon.ico":
            with open(file_path, 'rb') as f:
                content = f.read()
            content_length = len(content)
            headers = {
                "Content-Type": "image/x-icon",
                "Content-Length": content_length
            }
            return STATUS_OK, headers, content

        # Parse Range header
        ranges = re.findall(r'(\d*)-(\d*)', header) if header else []
        # Process Range headers
        boundary = uuid.uuid4().hex
        content_parts = []
        # 如果range size为1，表示只有一个区间
        if len(ranges) == 1:
            start, end = ranges[0]
            start, end = resolve_range(start, end, file_size)
            if start > end or end >= file_size:
                headers = {
                    "Content-Type": "text/html",
                    "Content-Length": 0,
                    "Content-Range": f"bytes */{file_size}"  # Indicate the valid size of the file
                }
                return STATUS_RANGE_NOT_SATISFIABLE, headers, "".encode()

            headers = {
                "Content-Type": mimetypes.guess_type(file_path)[0],
                "Content-Range": f"bytes {start}-{end}/{file_size}",
                "Content-Length": str(end - start + 1),
                "Accept-Ranges": "bytes"  # Indicate that server accepts range requests
            }
            with open(file_path, 'rb') as f:
                f.seek(start)
                content = f.read(end - start + 1).decode()
            return STATUS_PARTIAL_CONTENT, headers, content.encode()

        # 如果range size大于1，表示有多个区间
        for start, end in ranges:
            start, end = resolve_range(start, end, file_size)
            if start > end or end >= file_size:
                headers = {
                    "Content-Type": "text/html",
                    "Content-Length": 0,
                    "Content-Range": f"bytes */{file_size}"  # Indicate the valid size of the file
                }
                return STATUS_RANGE_NOT_SATISFIABLE, headers, ""
            part = f"--{boundary}\r\n"
            part += f"Content-Type: {mimetypes.guess_type(file_path)[0]}\r\n"
            part += f"Content-Range: bytes {start}-{end}/{file_size}\r\n\r\n"
            with open(file_path, 'rb') as f:
                f.seek(start)
                part += f.read(end - start + 1).decode()
            part += "\r\n"
            content_parts.append(part)

        # Combine the parts into the final payload
        content = "".join(content_parts) + f"--{boundary}--"
        content_length = len(content)

        # Set the appropriate headers for multipart response
        headers = {
            "Content-Type": f"multipart/byteranges; boundary={boundary}",
            "Content-Length": str(content_length)
        }
        return STATUS_PARTIAL_CONTENT, headers, content.encode()

    # 处理POST请求
    def handle_post_request(self, header, body, path):
        method = path.split("?")[0]
        if method == "/upload":
            return self.handle_upload(header, body, path)
        elif method == "/delete":
            requests = header + "\r\n\r\n" + body.decode()
            return self.handle_delete(requests, path)
        else:
            content = f'Unsupported method: {method}'
            return STATUS_METHOD_NOT_ALLOWED, 405, content.encode()

    # 处理DELETE请求
    def handle_delete(self, request, path):
        # 检查是否提供了正确的路径参数
        if not is_valid_path_parameter(path):
            return STATUS_BAD_REQUEST, 400, 'Bad Request'.encode()

        # 检查是否提供了正确的授权信息
        if_not_authorized, status, headers, info = self.is_authorized(request)
        if not if_not_authorized:
            return status, headers, info.encode()

        # 获取删除文件
        path_match = re.search(r'path=([^&\s]+)', path)
        delete_file = os.path.join(HEAD_PATH, path_match.group(1))

        # 检查目标删除文件是否存在
        if not os.path.exists(delete_file):
            return STATUS_NOT_FOUND, 404, 'Delete file not found'.encode()

        # 删除文件
        os.remove(delete_file)

        content = f'File deleted successfully to {delete_file}'
        return STATUS_OK, 200, content.encode()

    # 处理UPLOAD请求
    def handle_upload(self, header, body, path):
        # 检查是否提供了正确的路径参数
        if not is_valid_path_parameter(path):
            return STATUS_BAD_REQUEST, 400, 'Bad Request'.encode()

        # 检查是否提供了正确的授权信息
        if_not_authorized, status, headers, info = self.is_authorized(header)
        if not if_not_authorized:
            return status, headers, info.encode()

        # 获取上传目录
        path_match = re.search(r'path=([^&\s]+)', path)

        upload_dir = os.path.join(HEAD_PATH, path_match.group(1))
        print(os.path)
        # 检查目标上传目录是否存在
        if not os.path.exists(upload_dir):
            return STATUS_NOT_FOUND, 404, 'Upload directory not found'.encode()

        # 获取文件名
        filename_match = re.search(r'filename="([^"]+)"'.encode(), body)
        filename = filename_match.group(1) if filename_match else ''
        file_type = mimetypes.guess_type(filename.decode())[0]
        if not file_type.startswith('text'):
            # 提取 boundary
            boundary_match = re.search(r'\r\n--([^\s]+)--\r\n'.encode(), body)
            boundary = boundary_match.group(1) if boundary_match else ''

            file_match = body.split("--".encode() + boundary)[1] if boundary else ''
            file_content = re.search(r'.+?\r\n\r\n(.+)'.encode(), file_match, re.DOTALL).group(1)

            # 写入bytes
            with open(os.path.join(upload_dir, filename.decode()), 'wb') as file:
                file.write(file_content)

            content = f'File uploaded successfully to {upload_dir}/{filename}'
            return STATUS_OK, 200, content.encode()

        body = body.decode()
        # 提取 boundary
        boundary_match = re.search(r'boundary=([^\s]+)', header)
        boundary = boundary_match.group(1) if boundary_match else ''

        # 提取文件内容
        file_match = re.search(f'--{boundary}\r\n(.+)\r\n--{boundary}--', body, re.DOTALL)
        file = file_match.group(1) if file_match else ''
        file_content = re.search(r'.+?\r\n\r\n(.+)', file, re.DOTALL).group(1)

        # 保存上传的文件
        with open(os.path.join(upload_dir, filename.decode()), 'wb') as file:
            file.write(file_content.encode())

        content = f'File uploaded successfully to {upload_dir}/{filename.decode()}'
        return STATUS_OK, 200, content.encode()

    # 检查是否提供了正确的授权信息
    def is_authorized(self, request):
        # 从上传路径中提取用户名
        username = self.extract_username(request)

        # 检查用户是否认证
        if username not in self.users_account or not self.users_account[username]:
            return False, STATUS_UNAUTHORIZED, 401, 'Unauthorized'

        # 检查上传路径是否属于当前用户
        if not is_path_owned_by_user(request, username):
            return False, STATUS_FORBIDDEN, 403, 'Forbidden'

        return True, '', '', ''

    # 从请求中提取用户名
    def extract_username(self, request):
        if self.if_cookie == 0:
            # 从Authorization头中提取用户名
            auth_header = extract_authorization_header(request)
            if auth_header:
                auth_type, auth_value = auth_header.split(' ')
                username, password = base64.b64decode(auth_value).decode().split(':')
                return username
        else:
            # 从Cookie中提取用户名
            session_cookie = set_or_read_session_cookie(request)
            if session_cookie:
                session_id = session_cookie
                username, creation_time = self.sessions[session_id]
                return username


# 设置或读取会话Cookie
def set_or_read_session_cookie(request):
    # 从请求的Cookie中提取会话ID
    cookies = extract_cookies(request)
    session_cookie = cookies.get('session-id')
    return session_cookie


# 从请求头中提取Cookie
def extract_cookies(request):
    # 从请求头中提取Cookie
    request_lines = request.split('\r\n')
    cookies = {}
    for line in request_lines:
        if 'Cookie' in line:
            _, cookie_value = line.split(': ')
            cookie_pairs = cookie_value.split('; ')
            for pair in cookie_pairs:
                key, value = pair.split('=')
                cookies[key] = value
            break
    return cookies


# 获取Cookie的过期时间
def get_expiration_time():
    # 设置Cookie的过期时间（例如，30分钟）
    expiration_time = datetime.utcnow() + timedelta(minutes=30)
    # 格式化过期时间以符合HTTP头的要求
    return expiration_time.strftime("%a, %d %b %Y %H:%M:%S GMT")


# 检查是否提供了正确的路径参数
def is_valid_path_parameter(path):
    # 检查是否提供了正确的路径参数
    if 'path=' not in path:
        return False

    return True


# 使用 chunked 编码处理数据
def chunked_encoding(data, chunk_size=1024):
    """
    使用 chunked 编码处理数据
    """
    encoded_data = b""
    while data:
        chunk = data[:chunk_size]
        data = data[chunk_size:]
        chunk_length = f"{len(chunk):X}\r\n"
        encoded_data += chunk_length.encode() + chunk + b"\r\n"

    # 添加结束标志
    encoded_data += b"0\r\n\r\n"
    return encoded_data


# 生成HTML
def generate_html(access_path):
    dir = extract_path(access_path)
    parent_dir = os.path.dirname(dir.rstrip("/"))
    print(access_path)
    print(dir)
    print(parent_dir)

    content = "<h1>Files:</h1>"
    content += '<a href="#" onclick="getRoot()">/(Root)</a><br>'
    content += f'<a href="#" onclick="getParent(\'{parent_dir}\')">../(Parent)</a><br>'
    files = os.listdir(access_path)
    for file in files:
        # 在文件夹名字后面加斜杠
        file_link = f'<a href="#" onclick="getFile(\'{dir}\', \'{file}/\')">{file}/</a>' if os.path.isdir(
            os.path.join(access_path,
                         file)) else f'<a href="#" onclick="getFile(\'{dir}\', \'{file}\')">{file}</a>'
        content += f"<p>{file_link}</p>"
    content += '<div id="content"></div>'

    script_code = '''
                    <script>
                    function getRoot() {
                        window.location.href = '/?SUSTech-HTTP=0';
                    }                       
                    function getParent(parentDir) {
                        window.location.href = window.location.origin + parentDir + '?SUSTech-HTTP=0';
                    }
                    function getFile(sonDir, file) {
                        window.location.href = window.location.origin + sonDir + file + '?SUSTech-HTTP=0';
                    }
                </script>
                '''
    content += script_code
    return content


# 从上传路径中提取用户名
def is_path_owned_by_user(request, username):
    # 从上传路径中提取实际路径
    path_match = re.search(r'path=([^&\s]+)', request)
    if path_match:
        actual_path = path_match.group(1)
        user_directory = f'{username}/'
        return actual_path.startswith(user_directory)

    return False


# 从请求中提取用户名
def extract_authorization_header(request):
    # 从请求头中提取Authorization头
    request_lines = request.split('\r\n')
    for line in request_lines:
        if 'Authorization' in line:
            _, auth_value = line.split(': ')
            return auth_value
    return None


# 从请求中提取用户名
def extract_path(input_string):
    # 使用正则表达式找到 "data" 后面的部分
    match = re.search(r'data(.+)$', input_string)

    if match:
        # 获取匹配的部分
        matched_part = match.group(1)

        # 在匹配的部分中找到最后一个 "/"
        last_slash_index = matched_part.rfind('/')

        # 如果找到了 "/"，则截取字符串
        if last_slash_index != -1:
            result = matched_part[:last_slash_index + 1]
            return result

    # 如果没有找到匹配或者没有 "/"，返回原始字符串
    return input_string


def resolve_range(start_str, end_str, size):
    if start_str == '':
        # This means we have a -a range, return the last 'end' bytes
        end = size - 1
        start = size - int(end_str)
        return max(start, 0), end
    if end_str == '':
        # This means we have a n- range, return from byte n to the end
        return int(start_str), size - 1
    # Otherwise, we have a n-m range
    return int(start_str), int(end_str)


if __name__ == '__main__':
    # 创建HTTP服务器对象并启动服务器
    http_server = HTTPServer(HOST, PORT)
    # 启动服务器
    http_server.start()
