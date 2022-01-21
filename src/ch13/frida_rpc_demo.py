#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: frida_rpc_demo.py
@time: 2022/1/17 20:11
@project: python3-web-spider-learning
@desc: 13.9 基于Frida-RPC 模拟执行so文件（P683）
"""
import frida
import requests

BASE_URL = 'https://app9.scrape.center'
INDEX_URL = BASE_URL + '/api/movie?limit={limit}&offset={offset}&token={token}'
MAX_PAGE = 10
LIMIT = 10

session = frida.get_usb_device().attach('App9')
source = open('files/frida_rpc_app9.js', encoding='utf-8').read()
script = session.create_script(source)
script.load()


def get_token(string, offset):
    return script.exports.encrypt(string, offset)


for i in range(MAX_PAGE):
    offset = i * LIMIT
    token = get_token('/api/movie', offset)
    index_url = INDEX_URL.format(limit=LIMIT, offset=offset, token=token)
    response = requests.get(index_url)
    print('response', response.json())
