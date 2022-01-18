#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: httpx_demo.py
@time: 2022/1/4 11:32
@project: python3-web-spider-learning
@desc: 2.4 httpx的使用（P75~P78）
"""
import asyncio

import httpx


def httpx_deom():
    response = httpx.get('https://www.httpbin.org/get')
    print(response.status_code)
    print(response.headers)
    print(response.text)


def httpx_with_user_agent():
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko)'
                      'Chrome/52.0.2743.116 Safari/537.36'
    }
    response = httpx.get('https://www.httpbin.org/get', headers=headers)
    print(response.text)


def http2_demo():
    client = httpx.Client(http2=True)
    response = client.get('https://spa16.scrape.center/')
    print(response.text)


def client_demo():
    url = 'https://www.httpbin.org/headers'
    headers = {'User-Agent': 'my-app/0.0.1'}
    with httpx.Client(headers=headers) as client:
        r = client.get(url)
        print(r.json()['headers']['User-Agent'])


async def fetch(url):
    # 异步请求
    async with httpx.AsyncClient(http2=True) as client:
        response = await client.get(url)
        print(response.text)


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(fetch('https://www.httpbin.org/get'))
