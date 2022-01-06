#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: response_demo.py
@time: 2022/1/6 19:54
@project: python3-web-spider-learning
@desc: 响应（P205）
"""
import asyncio

import aiohttp


async def main():
    data = {
        'name': 'germey',
        'age': 25
    }
    async with aiohttp.ClientSession() as session:
        async with session.post('https://www.httpbin.org/post', data=data) as response:
            print('status:', response.status)
            print('headers:', response.headers)
            print('body:', await response.text())
            print('bytes:', await response.read())
            print('json:', await response.json())


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
