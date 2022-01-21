#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: requests_demo.py
@time: 2021/12/29 15:17
@project: python3-web-spider-learning
@desc: Request模块示例（P30~P34）
"""
import socket
import urllib.request
import urllib.error
import urllib.parse


def print_content(url='https://www.python.org'):
    response = urllib.request.urlopen(url)
    # 打印网页源代码
    print(response.read().decode('utf-8'))


def print_response_type(url='https://www.python.org'):
    response = urllib.request.urlopen(url)
    # 打印响应类型
    print(type(response))


def print_status(url='https://www.python.org'):
    response = urllib.request.urlopen(url)
    # 打印响应的状态码
    print(response.status)


def print_header(name='Server', url='https://www.python.org'):
    response = urllib.request.urlopen(url)
    # 打印响应的头信息
    print(response.getheaders())
    if name:
        # 打印响应头中的指定值
        print(response.getheader(name))


def print_content_with_data(url='https://www.httpbin.org/post'):
    data = bytes(urllib.parse.urlencode({'name': 'germey'}), encoding='utf-8')
    # 使用data参数
    response = urllib.request.urlopen(url, data=data)
    print(response.read().decode('utf-8'))


def print_content_with_timeout(url='https://www.httpbin.org/get'):
    # 使用timeout参数
    response = urllib.request.urlopen(url, timeout=0.1)
    print(response.read())


def print_content_with_try_except(url='https://www.httpbin.org/get'):
    # 使用timeout参数
    try:
        urllib.request.urlopen(url, timeout=0.1)
    except urllib.error.URLError as e:
        if isinstance(e.reason, socket.timeout):
            print('TIME OUT')


def print_content_with_request(url='https://www.httpbin.org/post'):
    # 指定headers的User-Agent和Host
    headers = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
        'Host': 'www.httpbin.org'
    }

    data_dict = {'name': 'germey'}
    # 将字典数据转成字节流格式
    data = bytes(urllib.parse.urlencode(data_dict), encoding='utf-8')
    # 构造Request类
    req = urllib.request.Request(url=url, data=data, headers=headers, method='POST')
    response = urllib.request.urlopen(req)
    print(response.read().decode('utf-8'))


if __name__ == '__main__':
    print_content_with_request()
