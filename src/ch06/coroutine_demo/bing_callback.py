#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: bing_callback.py
@time: 2022/1/6 18:53
@project: python3-web-spider-learning
@desc: 绑定回调（P196）
"""
import asyncio

import requests


async def request():
    url = 'https://www.baidu.com'
    status = requests.get(url)
    return status


def callback(task):
    print('Status:', task.result())


coroutine = request()
task = asyncio.ensure_future(coroutine)
task.add_done_callback(callback)
print('Task:', task)

loop = asyncio.get_event_loop()
loop.run_until_complete(task)
print('Task:', task)
