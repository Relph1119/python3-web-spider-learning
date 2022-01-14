#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: execjs_web_demo.py
@time: 2022/1/14 9:22
@project: python3-web-spider-learning
@desc: 11.7 浏览器环境下JavaScript的模拟执行（P457）
"""
import requests
from playwright.sync_api import sync_playwright

BASE_URL = "https://spa2.scrape.center"
INDEX_URL = BASE_URL + "/api/movie?limit={limit}&offset={offset}&token={token}"
MAX_PAGE = 10
LIMIT = 10

# 创建一个无头Chromium浏览器
context = sync_playwright().start()
browser = context.chromium.launch()
# 创建一个新页面
page = browser.new_page()
# 配置路由，将浏览器加载的js替换为本地js
page.route(
    "/js/chunk-10192a00.243cb8b7.js",
    lambda route: route.fulfill(path="files/chunk.js")
)
page.goto(BASE_URL)


def get_token(offset):
    # 使用evaluate方法模拟执行
    result = page.evaluate('''()=> {
        return window.encrypt("%s", "%s")
    }''' % ('/api/movie', offset))
    return result


for i in range(MAX_PAGE):
    offset = i * LIMIT
    token = get_token(offset)
    index_url = INDEX_URL.format(limit=LIMIT, offset=offset, token=token)
    response = requests.get(index_url)
    print('response:', response.json())
