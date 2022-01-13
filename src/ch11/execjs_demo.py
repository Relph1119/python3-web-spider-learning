#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: execjs_demo.py
@time: 2022/1/13 21:35
@project: python3-web-spider-learning
@desc: 11.5 使用Python模拟执行javascript（P446）
"""

import execjs
import json

item = {
    "name": "勒布朗-詹姆斯",
    "image": "james.png",
    "birthday": "1984-12-30",
    "height": "206cm",
    "weight": "113.4KG"
}

file = 'files/execjs_crypto.js'
node = execjs.get()
ctx = node.compile(open(file).read())

js = f"getToken({json.dumps(item, ensure_ascii=False)})"
print(js)
result = ctx.eval(js)
print(result)
