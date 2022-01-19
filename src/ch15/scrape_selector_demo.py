#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: scrape_selector_demo.py
@time: 2022/1/19 14:08
@project: python3-web-spider-learning
@desc: 15.3 Selector的使用（P754）
"""
from scrapy import Selector


def selector_demo():
    # 直接使用
    body = '<html><head><title>Hello World</title></head><body></body></html>'
    selector = Selector(text=body)
    title = selector.xpath('//title/text()').extract_first()
    print(title)


if __name__ == '__main__':
    selector_demo()
