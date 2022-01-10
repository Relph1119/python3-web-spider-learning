#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: css_locate_scrape.py
@time: 2022/1/10 21:45
@project: python3-web-spider-learning
@desc: 7.7 CSS位置偏移反爬与爬取实战（P282）
"""
import re

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from pyquery import PyQuery as pq


def parse_name(name_html):
    # 处理特殊的情况
    has_whole = name_html('.whole')
    if has_whole:
        return name_html.text()
    else:
        chars = name_html('.char')
        items = []
        for char in chars.items():
            # 提取文字和偏移值
            items.append({
                'text': char.text().strip(),
                'left': int(re.search('(\d+)px', char.attr('style')).group(1))
            })
        # 排序
        items = sorted(items, key=lambda x: x['left'], reverse=False)
        # 将文字组合在一起
        return ''.join([item.get('text') for item in items])


browser = webdriver.Chrome()
browser.get('https://antispider3.scrape.center/')
WebDriverWait(browser, 10) \
    .until(EC.presence_of_element_located((By.CSS_SELECTOR, '.item')))
html = browser.page_source
doc = pq(html)
names = doc('.item .name')
for name_html in names.items():
    name = parse_name(name_html)
    print(name)
browser.close()
