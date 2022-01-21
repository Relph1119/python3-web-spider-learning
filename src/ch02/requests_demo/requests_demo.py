#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: requests_demo.py
@time: 2021/12/31 13:52
@project: python3-web-spider-learning
@desc: requests基本用法（P48~P55）
"""
import os
import re

import requests


def print_get_request():
    r = requests.get('https://www.baidu.com')
    print(type(r))
    print(r.status_code)
    print(type(r.text))
    print(r.text[:100])
    print(r.cookies)


def print_request():
    r = requests.get('https://www.httpbin.org/get')
    r = requests.post('https://www.httpbin.org/post')
    r = requests.put('https://www.httpbin.org/put')
    r = requests.delete('https://www.httpbin.org/delete')
    r = requests.patch('https://www.httpbin.org/patch')


def print_get_with_params(url, params):
    r = requests.get(url, params=params)
    print(r.text)


def print_json():
    r = requests.get('https://www.httpbin.org/get')
    print(type(r.text))
    print(r.json())
    print(type(r.json()))


def fetch_web():
    r = requests.get('https://ssr1.scrape.center/')
    pattern = re.compile('<h2.*?>(.*?)</h2>', re.S)
    titles = re.findall(pattern, r.text)
    print(titles)


def get_favicon():
    if not os.path.exists('../files'):
        os.mkdir('../files')

    r = requests.get('https://scrape.center/favicon.ico')
    with open('../files/favicon.ico', 'wb') as f:
        f.write(r.content)


def print_get_with_headers():
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko)'
                      'Chrome/52.0.2743.116 Safari/537.36'
    }
    r = requests.get('https://ssr1.scrape.center/', headers=headers)
    print(r.text)


def print_post():
    data = {
        'name': 'germey',
        'age': '25'
    }
    r = requests.post("https://www.httpbin.org/post", data=data)
    print(r.text)


def check_request():
    r = requests.get('https://ssr1.scrape.center/')
    exit() if not r.status_code == requests.codes.ok else print('Request Successfully')


if __name__ == '__main__':
    # url = 'https://www.httpbin.org/get'
    # data = {
    #     'name': 'germey',
    #     'age': 25
    # }
    #
    # print_get_with_params(url, data)

    check_request()
