#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: simple_demo.py
@time: 2022/1/6 19:21
@project: python3-web-spider-learning
@desc: aiohttp基本实例（P202）
"""
import asyncio

import aiohttp


async def fetch(session, url):
    async with session.get(url) as response:
        return await response.text(), response.status


async def main():
    async with aiohttp.ClientSession() as session:
        html, status = await fetch(session, 'https://cuiqingcai.com')
        print(f'html: {html[:100]}...')
        print(f'status: {status}')


if __name__ == '__main__':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
