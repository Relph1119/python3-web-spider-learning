#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: nodejs_client.py
@time: 2022/1/13 22:13
@project: python3-web-spider-learning
@desc: Python调用Node.js服务（P453）
"""

import requests

data = {
    "name": "凯文-杜兰特",
    "image": "durant.png",
    "birthday": "1988-09-29",
    "height": "208cm",
    "weight": "108.9KG"
}

url = 'http://localhost:3000'
response = requests.post(url, json=data)
print(response.text)
