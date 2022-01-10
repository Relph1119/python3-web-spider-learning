#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: dev_mode.py
@time: 2022/1/10 9:27
@project: python3-web-spider-learning
@desc: 调试模式（P247）
"""
import asyncio

from pyppeteer import launch


async def main():
    browser = await launch(devtools=True, args=['--disable-infobars'])
    page = await browser.newPage()
    await page.goto('https://www.baidu.com')
    await asyncio.sleep(100)

asyncio.get_event_loop().run_until_complete(main())
