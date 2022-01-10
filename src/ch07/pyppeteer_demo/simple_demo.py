#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: simple_demo.py
@time: 2022/1/7 17:23
@project: python3-web-spider-learning
@desc: pyppeteer基本使用（P243）
"""
import asyncio
import os

from pyppeteer import launch
from pyquery import PyQuery as pq


async def simple_demo():
    browser = await launch()
    page = await browser.newPage()
    await page.goto('https://spa2.scrape.center/')
    await page.waitForSelector('.item .name')
    doc = pq(await page.content())
    names = [item.text() for item in doc('.item .name').items()]
    print('Name:', names)
    await browser.close()


async def simple_demo2():
    width, height = 1366, 768
    browser = await launch()
    page = await browser.newPage()
    await page.setViewport({'width': width, 'height': height})
    await page.goto('https://spa2.scrape.center/')
    await page.waitForSelector('.item .name')
    await asyncio.sleep(2)

    if not os.path.exists('files'):
        os.makedirs('files')

    await page.screenshot(path='files/example2.png')
    dimensions = await page.evaluate('''() =>{
        return {
            width: document.documentElement.clientWidth,
            height: document.documentElement.clientHeight,
            deviceScaleFactor: window.devicePixelRatio,
        }
    }''')

    print(dimensions)
    await browser.close()


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(simple_demo2())
