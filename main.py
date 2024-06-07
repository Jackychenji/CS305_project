# print("Hello!")
#
# import torch
#
# print(torch.__version__)
import re


def extract_path(input_string):
    # 使用正则表达式找到 "HTTP" 后面的部分
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


# 测试
input_strings = [
    "C:/Code/CS305_Project/HTTP/data/?SUSTech-HTTP=0",
    "C:/Code/CS305_Project/HTTP/data/12111511/",
    "C:/Code/CS305_Project/HTTP/data/12111511/mydata/"
]

for input_string in input_strings:
    result = extract_path(input_string)
    print(result)

import os

input_paths = ["/", "/12111511/", "/12111511/mydata/"]

for input_path in input_paths:
    # 删除最后一层级
    result = os.path.dirname(input_path.rstrip("/"))

    print(result)
