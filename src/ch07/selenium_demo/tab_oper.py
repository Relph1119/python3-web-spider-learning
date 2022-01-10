#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: tab_oper.py
@time: 2022/1/7 15:32
@project: python3-web-spider-learning
@desc: 选项卡管理（P222）
"""
import time

from selenium import webdriver

browser = webdriver.Chrome()
browser.get('https://www.baidu.com')
browser.execute_script('window.open()')
print(browser.window_handles)
browser.switch_to.window(browser.window_handles[1])
browser.get('https://www.taobao.com')
time.sleep(1)
browser.switch_to.window(browser.window_handles[0])
browser.get('https://python.org')