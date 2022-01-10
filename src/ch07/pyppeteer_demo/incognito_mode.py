#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: incognito_mode.py
@time: 2022/1/10 18:26
@project: python3-web-spider-learning
@desc: 无痕模式（P252）
"""
import asyncio

from pyppeteer import launch

width, height = 1366, 768


async def main():
    # 设置浏览器窗口大小
    browser = await launch(headless=False, args=['--disable-infobars', f'--window-size={width}, {height}'])
    context = await browser.createIncogniteBrowserContext()
    page = await context.newPage()
    # 设置页面大小
    await page.setViewport({'width': width, 'height': height})
    await page.goto('https://www.baidu.com/')
    await asyncio.sleep(100)


asyncio.get_event_loop().run_until_complete(main())
