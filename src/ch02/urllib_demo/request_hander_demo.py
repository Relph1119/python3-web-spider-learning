#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: request_hander_demo.py
@time: 2021/12/29 16:32
@project: python3-web-spider-learning
@desc: 验证、代理、Cookie（P35-P36）
"""

import http.cookiejar
import os
import urllib.request
from urllib.error import URLError
from urllib.request import HTTPPasswordMgrWithDefaultRealm, HTTPBasicAuthHandler
from urllib.request import ProxyHandler, build_opener


def valid():
    username = 'admin'
    password = 'admin'
    url = 'https://ssr3.scrape.center/'

    p = HTTPPasswordMgrWithDefaultRealm()
    p.add_password(None, url, username, password)
    auth_handler = HTTPBasicAuthHandler(p)
    opener = build_opener(auth_handler)

    try:
        result = opener.open(url)
        html = result.read().decode('utf-8')
        print(html)
    except URLError as e:
        print(e.reason)


def proxy():
    proxy_hander = ProxyHandler({
        'http': 'http://127.0.0.1:8080',
        'https': 'https://127.0.0.1:8080'
    })

    opener = build_opener(proxy_hander)
    try:
        response = opener.open('https://www.baidu.com')
        print(response.read().decode('utf-8'))
    except URLError as e:
        print(e.reason)


def cookie_values():
    # 声明CookieJar对象
    cookie = http.cookiejar.CookieJar()
    # 构建Handler
    handler = urllib.request.HTTPCookieProcessor(cookie)
    # 构建Opener
    opener = urllib.request.build_opener(handler)
    response = opener.open('https://www.baidu.com')
    for item in cookie:
        print(item.name + '=' + item.value)


def cookie_mozilla_content():
    if not os.path.exists('../files'):
        os.mkdir('../files')

    filename = 'files/mozilla_cookie.txt'
    cookie = http.cookiejar.MozillaCookieJar(filename)
    handler = urllib.request.HTTPCookieProcessor(cookie)
    opener = urllib.request.build_opener(handler)
    response = opener.open('https://www.baidu.com')
    cookie.save(ignore_discard=True, ignore_expires=True)


def cookie_lwp_content():
    if not os.path.exists('../files'):
        os.mkdir('../files')

    filename = 'files/lwp_cookie.txt'
    cookie = http.cookiejar.LWPCookieJar(filename)
    handler = urllib.request.HTTPCookieProcessor(cookie)
    opener = urllib.request.build_opener(handler)
    response = opener.open('https://www.baidu.com')
    cookie.save(ignore_discard=True, ignore_expires=True)


def cookie_use_lwp():
    cookie = http.cookiejar.LWPCookieJar()
    cookie.load('files/lwp_cookie.txt', ignore_discard=True, ignore_expires=True)
    handler = urllib.request.HTTPCookieProcessor(cookie)
    opener = urllib.request.build_opener(handler)
    response = opener.open('https://www.baidu.com')
    print(response.read().decode('utf-8'))


if __name__ == '__main__':
    valid()
