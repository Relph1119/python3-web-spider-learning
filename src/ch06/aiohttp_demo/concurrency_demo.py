#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: concurrency_demo.py
@time: 2022/1/6 20:01
@project: python3-web-spider-learning
@desc: 并发限制（P206）
"""
import asyncio

import aiohttp

CONCURRENCY = 5
URL = 'https://www.baidu.com'

semaphoer = asyncio.Semaphore(CONCURRENCY)
session = None


async def scrape_api():
    async with semaphoer:
        print('scraping', URL)
        async with session.get(URL) as response:
            await asyncio.sleep(1)
            return await response.text()


async def main():
    global session
    session = aiohttp.ClientSession()
    scrape_index_tasks = [asyncio.ensure_future(scrape_api()) for _ in range(10000)]
    await asyncio.gather(*scrape_index_tasks)


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
