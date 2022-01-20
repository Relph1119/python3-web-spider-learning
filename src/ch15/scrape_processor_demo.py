#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: scrape_processor_demo.py
@time: 2022/1/20 10:52
@project: python3-web-spider-learning
@desc: 15.12 Scrapy规则化爬虫（P816）
"""
from itemloaders.processors import TakeFirst, Join, Compose, MapCompose, SelectJmes


def takefirst():
    # 返回列表的第一个非空值
    processor = TakeFirst()
    print(processor(['', 1, 2, 3]))


def join():
    # 把列表拼接成字符串
    processor = Join()
    print(processor(['one', 'two', 'three']))

    processor = Join(',')
    print(processor(['one', 'two', 'three']))


def compose():
    # 使用多个函数组合构造而成
    processor = Compose(str.upper, lambda s: s.strip())
    print(processor(' hello world'))


def map_compose():
    # 和compose类似，迭代处理一个列表输入值
    processor = MapCompose(str.upper, lambda s: s.strip())
    print(processor(['Hello', 'World', 'Python']))


def select_jmes():
    # 查询JSON，传入Key，返回查询所得的Value
    processor = SelectJmes('foo')
    print(processor({'foo': 'bar'}))


if __name__ == '__main__':
    select_jmes()
