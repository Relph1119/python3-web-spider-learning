#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: text_oper_demo.py
@time: 2022/1/5 19:00
@project: python3-web-spider-learning
@desc: 4.1 TXT文本存储（P128~P130）
"""
import os
import re

import requests
from pyquery import PyQuery as pq

url = 'https://ssr1.scrape.center'
html = requests.get(url).text
doc = pq(html)
items = doc('.el-card').items()

if not os.path.exists('files'):
    os.makedirs('files')

file = open('files/movies.txt', 'w', encoding='utf-8')
for item in items:
    # 电影名称
    name = item.find('a > h2').text()
    file.write(f'名称：{name}\n')
    # 类别
    categories = [item.text() for item in item.find('.categories button span').items()]
    file.write(f'类别：{categories}\n')
    # 上映时间
    published_at = item.find('.info:contains(上映)').text()
    published_at = re.search('(\d{4}-\d{2}-\d{2})', published_at).group(1) \
        if published_at and re.search('(\d{4}-\d{2}-\d{2})', published_at) else None
    file.write(f'上映时间：{published_at}\n')
    # 评分
    score = item.find('p.score').text()
    file.write(f'评分：{score}\n')
    file.write(f'{"=" * 50}\n')

file.close()
