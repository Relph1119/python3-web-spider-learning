#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: simple_demo.py
@time: 2022/1/10 19:28
@project: python3-web-spider-learning
@desc: Playwright基本使用（P257）
"""
import asyncio
import os

from playwright.async_api import async_playwright
from playwright.sync_api import sync_playwright


def sync_demo():
    with sync_playwright() as p:
        for browser_type in [p.chromium, p.firefox, p.webkit]:
            browser = browser_type.launch(headless=False)
            page = browser.new_page()
            page.goto('https://www.baidu.com')

            if not os.path.exists('files'):
                os.makedirs('files')

            page.screenshot(path=f'files/screenshot-{browser_type.name}.png')
            print(page.title())
            browser.close()


async def async_demo():
    async with async_playwright() as p:
        for browser_type in [p.chromium, p.firefox, p.webkit]:
            browser = await browser_type.launch(headless=False)
            page = await browser.new_page()
            await page.goto('https://www.baidu.com')

            if not os.path.exists('files'):
                os.makedirs('files')

            await page.screenshot(path=f'files/screenshot-{browser_type.name}.png')
            print(await page.title())
            await browser.close()


if __name__ == '__main__':
    # 同步模式
    # sync_demo()

    # 异步模式
    asyncio.run(async_demo())