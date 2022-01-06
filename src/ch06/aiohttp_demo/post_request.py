#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: post_request.py
@time: 2022/1/6 19:52
@project: python3-web-spider-learning
@desc: POST请求（P203）
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
            print(await response.text())


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
