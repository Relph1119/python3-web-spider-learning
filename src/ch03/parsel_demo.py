#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: parsel_demo.py
@time: 2022/1/5 16:42
@project: python3-web-spider-learning
@desc: 3.4 parsel的使用（P124~P127）
"""
from parsel import Selector

html = '''
    <div>
        <ul>
             <li class="item-0">first item</li>
             <li class="item-1"><a href="link2.html">second item</a></li>
             <li class="item-0 active"><a href="link3.html"><span class="bold">third item</span></a></li>
             <li class="item-1 active"><a href="link4.html">fourth item</a></li>
             <li class="item-0"><a href="link5.html">fifth item</a></li>
         </ul>
     </div>
    '''


def parsel_demo():
    selector = Selector(text=html)
    items = selector.css('.item-0')
    print(len(items), type(items), items)
    items2 = selector.xpath('//li[contains(@class, "item-0")]')
    print(len(items2), type(items2), items2)


def extract_text():
    selector = Selector(text=html)
    items = selector.css('.item-0')
    for item in items:
        text = item.xpath('.//text()').get()
        print(text)

    result = selector.xpath('//li[contains(@class, "item-0")]//text()').getall()
    print(result)


def extract_attrs():
    selector = Selector(text=html)
    result = selector.css('.item-0.active a::attr(href)').get()
    print(result)

    result = selector.xpath('//li[contains(@class, "item-0") and contains(@class, "active")]/a/@href').get()
    print(result)


def extract_re():
    selector = Selector(text=html)
    result = selector.css('.item-0').re('link.*')
    print(result)

    result = selector.css('.item-0 *::text').re('.*item')
    print(result)

    result = selector.css('.item-0').re_first('<span class="bold">(.*?)</span>')
    print(result)


if __name__ == '__main__':
    extract_re()
