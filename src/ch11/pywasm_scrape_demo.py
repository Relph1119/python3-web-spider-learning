#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: pywasm_scrape_demo.py
@time: 2022/1/14 15:00
@project: python3-web-spider-learning
@desc: 11.11 WebAssembly案例分析和爬取实战（P495）
"""
import time

import pywasm
import requests

BASE_URL = 'https://spa14.scrape.center'
TOTAL_PAGE = 10

runtime = pywasm.load('files/Wasm.wasm')
for i in range(TOTAL_PAGE):
    offset = i * 10
    sign = runtime.exec('encrypt', [offset, int(time.time())])
    url = f'{BASE_URL}/api/movie/?limit=10&offset={offset}&sign={sign}'
    response = requests.get(url)
    print(response.json())
