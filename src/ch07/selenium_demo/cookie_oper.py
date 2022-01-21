#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: cookie_oper.py
@time: 2022/1/7 15:28
@project: python3-web-spider-learning
@desc: Cookie操作（P222）
"""
from selenium import webdriver

browser = webdriver.Chrome()
browser.get('https://www.zhihu.com/explore')
print(browser.get_cookies())
browser.add_cookie({'name': 'name',
                    'domain': 'www.zhihu.com',
                    'value': 'germey'})
print(browser.get_cookies())
browser.delete_all_cookies()
print(browser.get_cookies())
