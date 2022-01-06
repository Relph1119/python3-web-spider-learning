#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: timeout_demo.py
@time: 2022/1/6 19:58
@project: python3-web-spider-learning
@desc: 超时设置（P205）
"""
import asyncio

import aiohttp


async def main():
    timeout = aiohttp.ClientTimeout(total=1)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get('https://www.httpbin.org/get') as response:
            print('status:', response.status)


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
