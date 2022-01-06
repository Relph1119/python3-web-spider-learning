#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: url_params.py
@time: 2022/1/6 19:49
@project: python3-web-spider-learning
@desc: URL参数设置（P203）
"""
import asyncio

import aiohttp


async def main():
    params = {
        'name': 'germey',
        'age': 25
    }
    async with aiohttp.ClientSession() as session:
        async with session.get('https://www.httpbin.org/get', params=params) as response:
            print(await response.text())


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
