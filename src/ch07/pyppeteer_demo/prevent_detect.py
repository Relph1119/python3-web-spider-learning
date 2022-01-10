#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: prevent_detect.py
@time: 2022/1/10 18:12
@project: python3-web-spider-learning
@desc: 防止检测（P248-P250）
"""
import asyncio

from pyppeteer import launch

width, height = 1366, 768


async def main():
    # 设置浏览器窗口大小
    browser = await launch(headless=False, args=['--disable-infobars', f'--window-size={width}, {height}'])
    page = await browser.newPage()
    # 设置页面大小
    await page.setViewport({'width': width, 'height': height})
    await page.evaluateOnNewDocument('Object.defineProperty(navigator, "webdriver", {get: ()=> undefined})')
    await page.goto('https://antispider1.scrape.center/')
    await asyncio.sleep(100)


asyncio.get_event_loop().run_until_complete(main())
