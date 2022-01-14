#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: wasmer_scrape_demo.py
@time: 2022/1/14 17:08
@project: python3-web-spider-learning
@desc: wasmer库实战
"""
import time

import requests
from wasmer import engine, Store, Module, Instance
from wasmer_compiler_cranelift.wasmer_compiler_cranelift import Compiler

# 读取wasm文件
store = Store(engine.JIT(Compiler))
module = Module(store, open('files/Wasm.wasm', 'rb').read())
instance = Instance(module)

BASE_URL = 'https://spa14.scrape.center'
TOTAL_PAGE = 10

for i in range(TOTAL_PAGE):
    offset = i * 10
    sign = instance.exports.encrypt(offset, int(time.time()))
    url = f'{BASE_URL}/api/movie/?limit=10&offset={offset}&sign={sign}'
    response = requests.get(url)
    print(response.json())