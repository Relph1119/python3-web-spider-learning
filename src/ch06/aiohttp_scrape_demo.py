#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: aiohttp_scrape_demo.py
@time: 2022/1/6 20:06
@project: python3-web-spider-learning
@desc: 6.3 aiohttp异步爬取实战（P207~P211）
"""
import asyncio
import json
import logging
from aiohttp import TCPConnector
import aiohttp
from motor.motor_asyncio import AsyncIOMotorClient

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s: %(message)s')

INDEX_URL = 'https://spa5.scrape.center/api/book?limit=18&offset={offset}'
DETAIL_URL = 'https://spa5.scrape.center/api/book/{id}'
PAGE_SIZE = 18
PAGE_NUMBER = 100
CONCURRENCY = 5

semaphore = asyncio.Semaphore(CONCURRENCY)
session = None


async def scrape_api(url):
    """
    通用爬取方法
    """
    async with semaphore:
        try:
            logging.info('scraping %s', url)
            async with session.get(url) as response:
                return await response.json()
        except aiohttp.ClientError:
            logging.error('error occurred with scaping %s', url, exc_info=True)


async def scrape_index(page):
    """
    爬取列表页
    """
    url = INDEX_URL.format(offset=PAGE_SIZE * (page - 1))
    return await scrape_api(url)


MONGO_CONNECTION_STRING = 'mongodb://localhost:27017'
MONGO_DB_NAME = 'books'
MONGO_COLLECTION_NAME = 'books'

client = AsyncIOMotorClient(MONGO_CONNECTION_STRING)
db = client[MONGO_DB_NAME]
collection = db[MONGO_COLLECTION_NAME]


async def save_data(data):
    logging.info('saving data %s', data)
    if data:
        return await collection.update_one({
            'id': data.get('id')
        }, {
            '$set': data
        }, upsert=True)


async def scrape_detail(id):
    url = DETAIL_URL.format(id=id)
    data = await scrape_api(url)
    await save_data(data)


async def main():
    global session
    session = aiohttp.ClientSession(connector=TCPConnector(ssl=False))
    scrape_index_tasks = [asyncio.ensure_future(scrape_index(page)) for page in range(1, PAGE_NUMBER + 1)]
    results = await asyncio.gather(*scrape_index_tasks)
    logging.info('results %s', json.dumps(results, ensure_ascii=False, indent=2))

    # 所有书的ID
    ids = []
    for index_data in results:
        if not index_data:
            continue
        for item in index_data.get('results'):
            ids.append(item.get('id'))

    scrape_detail_tasks = [asyncio.ensure_future(scrape_detail(id)) for id in ids]
    await asyncio.wait(scrape_detail_tasks)
    await session.close()


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
