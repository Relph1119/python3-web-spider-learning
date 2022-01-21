#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: ida_demo.py
@time: 2022/1/17 19:19
@project: python3-web-spider-learning
@desc: 13.8 IDA Pro静态分析和动态调试so文件（汇编代码调试）（P679）
"""
import requests
import hashlib
import time
import base64


def get_token(value, offset):
    array = []
    array.append(value)
    array.append('9fdLnciVh4FxQbri')
    array.append(str(offset))
    timestamp = str(int(time.time()))
    array.append(timestamp)
    sign = hashlib.sha1(','.join(array).encode('utf-8')).hexdigest()
    return base64.b64encode(','.join([sign, timestamp]).encode('utf-8')).decode('utf-8')


INDEX_URL = 'https://app8.scrape.center/api/movie?limit={limit}&offset={offset}&token={token}'
MAX_PAGE = 10
LIMIT = 10


for i in range(MAX_PAGE):
    offset = i * LIMIT
    token = get_token('/api/movie', offset)
    index_url = INDEX_URL.format(limit=LIMIT, offset=offset, token=token)
    response = requests.get(index_url)
    print('response', response.json())
