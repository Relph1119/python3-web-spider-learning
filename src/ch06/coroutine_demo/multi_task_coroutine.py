#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: multi_task_coroutine.py
@time: 2022/1/6 18:58
@project: python3-web-spider-learning
@desc: 多任务协程（P196）
"""
import asyncio

import requests


async def request():
    url = 'https://www.baidu.com'
    status = requests.get(url)
    return status


tasks = [asyncio.ensure_future(request()) for _ in range(5)]
print('Task:', tasks)

loop = asyncio.get_event_loop()
loop.run_until_complete(asyncio.wait(tasks))

for task in tasks:
    print('Task Result:', task.result())
