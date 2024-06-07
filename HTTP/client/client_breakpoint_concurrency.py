# client2.py
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
# 定义服务器地址和端口
HOST = 'localhost'
PORT = 8080

# 定义并发线程数量
CONCURRENT_REQUESTS = 1000

# 定义文件请求范围
RANGES = [f'{i}-{i+99}' for i in range(0, 1000, 10)]

start_event = threading.Event()


def make_range_request(range_value):
    # 等待事件被设置，然后开始执行
    start_event.wait()

    # 创建套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    # 发送带有Range头的HTTP请求
    range_header = f'Range: bytes={range_value}\r\nAuthorization: Basic Y2xpZW50MToxMjM=\r\n'
    request = f'GET /test.txt HTTP/1.1\r\nHost: {HOST}\r\n{range_header}\r\n'
    sock.sendall(request.encode())

    # 接收响应
    response = b''

    part = sock.recv(1024)

    response += part

    # 关闭连接
    sock.close()
    return f'Response for range {range_value}:\n{response.decode()}'


# 使用线程池进行并发请求
with ThreadPoolExecutor(max_workers=CONCURRENT_REQUESTS) as executor:
    # 提交所有请求到线程池，但是它们会等待start_event
    future_to_range = {executor.submit(make_range_request, r): r for r in RANGES}

    # 在这里等待，直到准备好开始任务
    input("Press enter to start tasks...")
    start_event.set()  # 触发事件，任务开始执行

    # 按照请求完成的顺序处理结果
    for future in future_to_range.keys():
        try:
            data = future.result()
            print(data)
        except Exception as exc:
            range_value = future_to_range[future]
            print(f'{range_value} generated an exception: {exc}')