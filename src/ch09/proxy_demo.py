#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: urllib_proxy.py
@time: 2022/1/11 17:01
@project: python3-web-spider-learning
@desc: 9.1 代理的设置（P332-P340）
"""
import socket
from urllib import request
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

import aiohttp
import httpx
import requests
import socks
from aiohttp_socks import ProxyConnector
from httpx_socks import SyncProxyTransport, AsyncProxyTransport
from playwright.sync_api import sync_playwright
from pyppeteer import launch
from selenium import webdriver


def urllib_http_proxy():
    proxy = '127.0.0.1:19180'
    proxy_handler = ProxyHandler({
        'http': 'http://' + proxy,
        'https': 'http://' + proxy
    })

    opener = build_opener(proxy_handler)
    try:
        response = opener.open('http://www.httpbin.org/get')
        print(response.read().decode('utf-8'))
    except URLError as e:
        print(e.reason)


def urllib_socks_proxy():
    socks.set_default_proxy(socks.SOCKS5, '127.0.0.1', 19181)
    socket.socket = socks.socksocket
    try:
        response = request.urlopen('http://www.httpbin.org/get')
        print(response.read().decode('utf-8'))
    except URLError as e:
        print(e.reason)


def requests_http_proxy():
    proxy = '127.0.0.1:19180'
    proxies = {
        'http': 'http://' + proxy,
        'https': 'http://' + proxy
    }
    try:
        response = requests.get('https://www.httpbin.org/get', proxies=proxies)
        print(response.text)
    except requests.exceptions.ConnectionError as e:
        print('Error', e.args)


def requests_socks_proxy():
    proxy = '127.0.0.1:19181'
    proxies = {
        'http': 'socks5://' + proxy,
        'https': 'socks5://' + proxy
    }
    try:
        response = requests.get('https://www.httpbin.org/get', proxies=proxies)
        print(response.text)
    except requests.exceptions.ConnectionError as e:
        print('Error', e.args)


def httpx_http_proxy():
    proxy = '127.0.0.1:19180'
    proxies = {
        'http://': 'http://' + proxy,
        'https://': 'http://' + proxy
    }

    with httpx.Client(proxies=proxies) as client:
        response = client.get('https://www.httpbin.org/get')
        print(response.text)


def httpx_sync_socks_proxy():
    transport = SyncProxyTransport.from_url('socks5://127.0.0.1:19181')

    with httpx.Client(transport=transport) as client:
        response = client.get('https://www.httpbin.org/get')
        print(response.text)


async def httpx_async_socks_proxy():
    transport = AsyncProxyTransport.from_url('socks5://127.0.0.1:19181')
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get('https://www.httpbin.org/get')
        print(response.text)


def selenium_http_proxy():
    proxy = '127.0.0.1:19180'
    options = webdriver.ChromeOptions()
    options.add_argument('--proxy-server=http://' + proxy)
    browser = webdriver.Chrome(options=options)
    browser.get('https://www.httpbin.org/get')
    print(browser.page_source)
    browser.close()


def selenium_socks_proxy():
    proxy = '127.0.0.1:19181'
    options = webdriver.ChromeOptions()
    options.add_argument('--proxy-server=socks5://' + proxy)
    browser = webdriver.Chrome(options=options)
    browser.get('https://www.httpbin.org/get')
    print(browser.page_source)
    browser.close()


async def aiohttp_http_proxy():
    proxy = 'http://127.0.0.1:19180'
    async with aiohttp.ClientSession() as session:
        async with session.get('https://www.httpbin.org/get', proxy=proxy) as response:
            print(await response.text())


async def aiohttp_socks_proxy():
    connector = ProxyConnector.from_url('socks5://127.0.0.1:19181')
    async with aiohttp.ClientSession(connector=connector) as session:
        async with session.get('https://www.httpbin.org/get') as response:
            print(await response.text())


async def pyppeteer_http_proxy():
    proxy = '127.0.0.1:19180'
    browser = await launch({'arg': ['--proxy-server=http://' + proxy], 'headless': False})
    page = await browser.newPage()
    await page.goto('https://www.httpbin.org/get')
    print(await page.content())
    await browser.close()


async def pyppeteer_socks_proxy():
    proxy = '127.0.0.1:19181'
    browser = await launch({'arg': ['--proxy-server=socks5://' + proxy], 'headless': False})
    page = await browser.newPage()
    await page.goto('https://www.httpbin.org/get')
    print(await page.content())
    await browser.close()


def playwright_http_proxy():
    with sync_playwright() as p:
        browser = p.chromium.launch(proxy={
            'server': 'http://127.0.0.1:19180'
        })
        page = browser.new_page()
        page.goto('https://www.httpbin.org/get')
        print(page.content())
        browser.close()


def playwright_socks_proxy():
    with sync_playwright() as p:
        browser = p.chromium.launch(proxy={
            'server': 'socks5://127.0.0.1:19181'
        })
        page = browser.new_page()
        page.goto('https://www.httpbin.org/get')
        print(page.content())
        browser.close()


if __name__ == '__main__':
    playwright_socks_proxy()
    # asyncio.get_event_loop().run_until_complete(pyppeteer_socks_proxy())
