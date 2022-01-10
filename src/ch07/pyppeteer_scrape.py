#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: pyppeteer_scrape.py
@time: 2022/1/10 21:21
@project: python3-web-spider-learning
@desc: 7.6 Pyppeteer爬取实战（P276）
"""
import asyncio
import json
import logging
import os

from pyppeteer.errors import TimeoutError

from pyppeteer import launch

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

INDEX_URL = 'https://spa2.scrape.center/page/{page}'
TIME_OUT = 10
TOTAL_PAGE = 10
WINDOW_WIDTH, WINDOW_HEIGHT = 1366, 768
HEADLESS = False

browser, tab = None, None


async def init():
    global browser, tab
    browser = await launch(headless=HEADLESS,
                           args=['--disable-infobars',
                                 f'--widow-size={WINDOW_WIDTH}, {WINDOW_HEIGHT}'])
    tab = await browser.newPage()
    await tab.setViewport({'width': WINDOW_WIDTH, 'height': WINDOW_HEIGHT})


async def scrape_page(url, selector):
    """
    爬取网页
    """
    logging.info('scraping %s', url)
    try:
        await tab.goto(url)
        await tab.waitForSelector(selector, options={
            'timeout': TIME_OUT * 1000
        })
    except TimeoutError:
        logging.error('error occurred while scraping %s', url, exc_info=True)


async def scrape_index(page):
    """
    爬取列表页
    """
    url = INDEX_URL.format(page=page)
    # 当电影名全部加载完成，表示页面加载成功
    await scrape_page(url, '.item .name')


async def parse_index():
    """
    解析列表页
    """
    return await tab.querySelectorAllEval('.item .name', 'nodes => nodes.map(node => node.href)')


async def scrape_detail(url):
    """
    爬取详情页
    """
    await scrape_page(url, 'h2')


async def parse_detail():
    url = tab.url
    name = await tab.querySelectorEval('h2', 'node => node.innerText')
    categories = await tab.querySelectorAllEval('.categories button span', 'nodes => nodes.map(node => node.innerText)')
    cover = await tab.querySelectorEval('.cover', 'node => node.src')
    score = await tab.querySelectorEval('.score', 'node => node.innerText')
    drama = await tab.querySelectorEval('.drama p', 'node => node.innerText')
    return {
        'url': url,
        'name': name,
        'categories': categories,
        'cover': cover,
        'score': score,
        'drama': drama
    }

RESULT_DIR = 'results'

if not os.path.exists(RESULT_DIR):
    os.makedirs(RESULT_DIR)


async def save_data(data):
    """
    保存数据
    """
    name = data.get('name')
    data_path = f'{RESULT_DIR}/{name}.json'
    json.dump(data, open(data_path, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)


async def main():
    await init()
    try:
        for page in range(1, TOTAL_PAGE + 1):
            await scrape_index(page)
            detail_urls = await parse_index()
            for detail_url in detail_urls:
                await scrape_detail(detail_url)
                detail_data = await parse_detail()
                logging.info('detail data %s', detail_data)
                logging.info('saving data to json file')
                await save_data(detail_data)
                logging.info('data saved successfully')
    finally:
        await browser.close()


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
