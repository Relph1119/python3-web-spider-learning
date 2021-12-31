#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: parse_demo.py
@time: 2021/12/29 16:49
@project: python3-web-spider-learning
@desc: parse模块示例（P40~P44）
"""
from urllib.parse import urlparse, urlunparse, urlsplit, urlunsplit, urljoin, urlencode, parse_qs, parse_qsl, quote, \
    unquote


class UrlLibDemo:
    def __init__(self):
        self.base_url = None
        self.scheme = ''
        self.allow_fragments = True
        self.data = None

    def print_urlparse(self):
        # 对一个URL进行解析
        result = urlparse(self.base_url, scheme=self.scheme, allow_fragments=self.allow_fragments)
        print(type(result))
        print(result)

    def print_urlunparse(self):
        # 构造一个URL
        print(urlunparse(self.data))

    def print_urlsplit(self):
        # 解析整个url，并返回5个部分
        print(urlsplit(self.base_url))

    def print_urlunsplit(self):
        # 将链接各个部分组合成完整链接
        print(urlunsplit(self.data))

    def print_urljoin(self, other_url):
        # 分析base_url的scheme、netloc和path这3个内容，并对新链接缺失的部分进行补充
        print(urljoin(self.base_url, other_url))

    def print_urlencode(self, params):
        # 将params字典转换成URL的Get请求
        print(self.base_url + urlencode(params))

    def print_parse_qs(self, query):
        # 将一串Get请求参数转回字典
        print(parse_qs(query))

    def print_parse_qsl(self, query):
        # 将一串Get请求参数转回元组
        print(parse_qsl(query))

    def print_quote(self, keyword):
        # 将内容转化为URL编码格式
        print(self.base_url + quote(keyword))

    def print_unquote(self):
        # 对URL进行解码
        print(unquote(self.base_url))


if __name__ == '__main__':
    urllib_demo = UrlLibDemo()
    # urllib_demo.base_url = 'https://www.baidu.com/index.html#comment'
    # urllib_demo.allow_fragments = False
    #
    # urllib_demo.print_urlparse()

    # urllib_demo.data = ['https', 'www.baidu.com', 'index.html', 'user', 'a=6', 'comment']
    # urllib_demo.print_urlunparse()

    # urllib_demo.base_url = 'https://www.baidu.com/index.html;user?id=5#comment'
    # urllib_demo.print_urlsplit()

    # urllib_demo.data = ['https', 'www.baidu.com', 'index.html', 'a=6', 'comment']
    # urllib_demo.print_urlunsplit()

    # urllib_demo.base_url = 'https://www.baidu.com'
    # urllib_demo.print_urljoin('FAQ.html')

    # urllib_demo.base_url = 'https://www.baidu.com?'
    # params = {
    #     'name': 'germey',
    #     'age': 25
    # }
    # urllib_demo.print_urlencode(params)

    # query = 'name=germey&age=25'
    # urllib_demo.print_parse_qs(query)

    # urllib_demo.print_parse_qsl(query)

    # keyword = '壁纸'
    # urllib_demo.base_url = 'https://www.baidu.com/s?wd='
    # urllib_demo.print_quote(keyword)

    urllib_demo.base_url = 'https://www.baidu.com/s?wd=%E5%A3%81%E7%BA%B8'
    urllib_demo.print_unquote()
