#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: coroutine_await_aiohttp.py
@time: 2022/1/6 19:05
@project: python3-web-spider-learning
@desc: 协程实现，await、aiohttp的使用（P197）
"""
import asyncio
import time

import aiohttp

start = time.time()


async def get(url):
    session = aiohttp.ClientSession()
    response = await session.get(url)
    await response.text()
    await session.close()
    return response


async def request():
    url = 'https://www.httpbin.org/delay/5'
    print('Waiting for', url)
    response = await get(url)
    print('Get response from', url, 'response', response)


tasks = [asyncio.ensure_future(request()) for _ in range(10)]
loop = asyncio.get_event_loop()
loop.run_until_complete(asyncio.wait(tasks))

end = time.time()
print('Cost time:', end - start)
