#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: run.py
@time: 2022/1/20 9:19
@project: python3-web-spider-learning
@desc: 15.11 Scrapy对接Pyppeteer（P807）
"""
from scrapy.cmdline import execute

execute(['scrapy', 'crawl', 'book'])
