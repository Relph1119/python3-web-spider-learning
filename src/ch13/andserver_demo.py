#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: andserver_demo.py
@time: 2022/1/17 23:07
@project: python3-web-spider-learning
@desc: 13.10 基于AndServer-RPC模拟执行so文件（Python爬取数据）（P691）
"""
import requests

BASE_URL = 'https://app9.scrape.center'
INDEX_URL = BASE_URL + '/api/movie?limit={limit}&offset={offset}&token={token}'
ANDSERVER_URL = 'http://localhost:8080/encrypt?string={string}&offset={offset}'
MAX_PAGE = 10
LIMIT = 10


def get_token(string, offset):
    andserver_url = ANDSERVER_URL.format(string=string, offset=offset)
    return requests.get(andserver_url).json().get('sign')


for i in range(MAX_PAGE):
    offset = i * LIMIT
    token = get_token("/api/movie", offset)
    index_url = INDEX_URL.format(limit=LIMIT, offset=offset, token=token)
    response = requests.get(index_url)
    print("response:", response.json())
