# CS305_Project

### 2023/12/13 初步框架 和 View and Download

- 项目代码放在`HTTP`根目录里面，所有需要访问的数据在`/HTTP/data`里面，目前`server.py`里面采用的是绝对路径的方式，可以需要根据实际情况改一改
- 处理结果统一采用返回`Status_code, Header, Body`这三个参数的方式
- `AUTH_FLAG = 1`的时候开启验证，其他时候停用验证，如果想用浏览器直接访问需要停用验证。用APIfox的话可以加上验证。