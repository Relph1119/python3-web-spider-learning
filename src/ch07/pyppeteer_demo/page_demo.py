#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: page_demo.py
@time: 2022/1/10 18:29
@project: python3-web-spider-learning
@desc: Page对象示例（P253~P256）
"""
import asyncio

from pyppeteer import launch


async def page_selector():
    browser = await launch()
    page = await browser.newPage()
    await page.goto('https://spa2.scrape.center/')
    await page.waitForSelector('.item .name')
    j_result1 = await page.J('.item .name')
    j_result2 = await page.querySelector('.item .name')
    jj_result1 = await page.JJ('.item .name')
    jj_result2 = await page.querySelectorAll('.item .name')
    print('J Result1:', j_result1)
    print('J Result2:', j_result2)
    print('JJ Result1:', jj_result1)
    print('JJ Result2:', jj_result2)
    await browser.close()


async def tab_oper():
    browser = await launch(headless=False)
    page = await browser.newPage()
    await page.goto('https://www.baidu.com')
    page = await browser.newPage()
    await page.goto('https://www.bing.com')
    pages = await browser.pages()
    print('Pages:', pages)
    page1 = pages[1]
    # 选择页面1
    await page1.bringToFront()
    await asyncio.sleep(100)


async def page_oper():
    browser = await launch(headless=False)
    page = await browser.newPage()
    await page.goto('https://dynamic1.scrape.cuiqingcai.com/')
    await page.goto('https://spa2.scrape.center/')

    # 后退
    await page.goBack()
    # 前进
    await page.goForward()
    # 刷新
    await page.reload()
    # 保存PDF
    await page.pdf()
    # 截图
    await page.screenshot()
    # 设置页面HTML
    await page.setContent('<h2>Hello World</h2>')
    # 设置User-Agent
    await page.setUserAgent('Python')
    # 设置Headers
    await page.setExtraHttpHeaders(headers={})
    # 关闭
    await page.close()
    await browser.close()


async def page_click():
    browser = await launch(headless=False)
    page = await browser.newPage()
    await page.goto('https://spa2.scrape.center')
    await page.waitForSelector('.item .name')
    await page.click('.item .name', options={
        'button': 'right',
        'clickCount': 1,
        'delay': 3000,
    })
    await browser.close()


async def input_text():
    browser = await launch(headless=False)
    page = await browser.newPage()
    await page.goto('https://www.taobao.com')
    # 后退
    await page.type('#q', 'iPad')
    # 关闭
    await asyncio.sleep(10)
    await browser.close()


async def get_info():
    browser = await launch(headless=False)
    page = await browser.newPage()
    await page.goto('https://spa2.scrape.center/')
    print('HTML:', await page.content())
    print('Cookies:', await page.cookies())
    await browser.close()


async def eval():
    width, height = 1366, 768

    browser = await launch()
    page = await browser.newPage()
    await page.setViewport({'width': width, 'height': height})
    await page.goto('https://spa2.scrape.center/')
    await page.waitForSelector('.item .name')
    await asyncio.sleep(2)
    await page.screenshot(path='files/eval_example.png')
    dimensions = await page.evaluate('''() => {
        return {
            width: document.documentElement.clientWidth,    
            height: document.documentElement.clientHeight,    
            deviceScaleFactor: window.devicePixelRatio,    
        }
    }''')
    print(dimensions)
    await browser.close()


if __name__ == '__main__':
    # 选择器
    # asyncio.get_event_loop().run_until_complete(page_selector())

    # 选项卡操作
    # asyncio.get_event_loop().run_until_complete(tab_oper())

    # 页面操作
    # asyncio.get_event_loop().run_until_complete(page_oper())

    # 点击
    # asyncio.get_event_loop().run_until_complete(page_click())

    # 输入文本
    # asyncio.get_event_loop().run_until_complete(input_text())

    # 获取信息
    # asyncio.get_event_loop().run_until_complete(get_info())

    # 执行
    asyncio.get_event_loop().run_until_complete(eval())
