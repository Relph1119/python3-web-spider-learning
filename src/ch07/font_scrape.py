#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: font_scrape.py
@time: 2022/1/10 21:55
@project: python3-web-spider-learning
@desc: 7.8 字体反爬与爬取案例（P287）
难点：评分是通过CSS样式控制的
"""
import re

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
from pyquery import PyQuery as pq

url = 'https://antispider4.scrape.center/css/app.654ba59e.css'

response = requests.get(url)
pattern = re.compile('.icon-(.*?):before\{content:"(.*?)"\}')
results = re.findall(pattern, response.text)
icon_map = {item[0]: item[1] for item in results}


def parse_score(item):
    elements = item('.icon')
    icon_values = []
    for element in elements.items():
        class_name = (element.attr('class'))
        # 提取CSS的icon代号
        icon_key = re.search('icon-(\d+)', class_name).group(1)
        # 得到真实值
        icon_value = icon_map.get(icon_key)
        icon_values.append(icon_value)
    # 将值进行连接，组成score
    return ''.join(icon_values)


browser = webdriver.Chrome()
browser.get('https://antispider4.scrape.center/')
WebDriverWait(browser, 10) \
    .until(EC.presence_of_element_located((By.CSS_SELECTOR, '.item')))
html = browser.page_source
doc = pq(html)
items = doc('.item')
for item in items.items():
    name = item('name').text()
    categories = [o.text() for o in item('.categories button').items()]
    score = parse_score(item)
    print(f'name: {name} categories: {categories} score: {score}')
browser.close()
