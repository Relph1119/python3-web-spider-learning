#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: advanced_use.py
@time: 2021/12/31 15:13
@project: python3-web-spider-learning
@desc: 高级用法（P55~P63）
"""
import requests
import urllib3
from requests import Session, Request

urllib3.disable_warnings()


def upload_file():
    files = {
        'file': open('../files/favicon.ico', 'rb')
    }
    r = requests.post('https://www.httpbin.org/post', files=files)
    print(r.text)


def print_cookie():
    r = requests.get('https://www.baidu.com')
    print(r.cookies)
    for key, value in r.cookies.items():
        print(key + '=' + value)


def print_https_with_verify():
    r = requests.get('https://ssr2.scrape.center/', verify=False)
    print(r.status_code)


def print_with_timeout():
    r = requests.get('https://www.httpbin.org/get', timeout=1)
    print(r.status_code)


def print_with_auth():
    r = requests.get('https://ssr3.scrape.center/', auth=('admin', 'admin'))
    print(r.status_code)


def print_prepared_request():
    url = 'https://www.httpbin.org/post'
    data = {'name': 'germey'}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko)'
                      'Chrome/52.0.2743.116 Safari/537.36'
    }
    s = Session()
    req = Request('POST', url, data=data, headers=headers)
    prepped = s.prepare_request(req)
    r = s.send(prepped)
    print(r.text)


if __name__ == '__main__':
    print_prepared_request()
