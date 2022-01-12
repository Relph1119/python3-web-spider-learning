#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: antispider_scrape_with_account_pool.py
@time: 2022/1/12 17:18
@project: python3-web-spider-learning
@desc: 使用账号池爬取网页
"""
import asyncio
from pyquery import PyQuery as pq
from loguru import logger
import aiohttp
from aiohttp import TCPConnector

MAX_ID = 20
CONCURRENCY = 2
TARGET_URL = 'https://antispider6.scrape.center'
ACCOUNT_POOL_URL = 'http://localhost:6789/antispider6/random'

semaphore = asyncio.Semaphore(CONCURRENCY)


async def parse_detail(html):
    doc = pq(html)
    title = doc('.item h2').text()
    categories = [item.text() for item in doc('.item .categories span').items()]
    cover = doc('.item .cover').attr('src')
    score = doc('.item .score').text()
    drama = doc('.item .drama').text().strip()

    return {
        'title': title,
        'categories': categories,
        'cover': cover,
        'score': score,
        'drama': drama
    }


async def fetch_credential(session):
    async with session.get(ACCOUNT_POOL_URL) as response:
        return await response.text()


async def scrape_detail(session, url):
    async with semaphore:
        credential = await fetch_credential(session)
        headers = {'cookie': credential}
        logger.debug(f'scrape {url} using credential {credential}')
        async with session.get(url, headers=headers) as response:
            html = await response.text()
            data = await parse_detail(html)
            logger.debug(f'data {data}')


async def main():
    session = aiohttp.ClientSession(connector=TCPConnector(ssl=False))
    tasks = []
    for i in range(1, MAX_ID + 1):
        url = f'{TARGET_URL}/detail/{i}'
        task = asyncio.ensure_future(scrape_detail(session, url))
        tasks.append(task)
    await asyncio.gather(*tasks)


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
