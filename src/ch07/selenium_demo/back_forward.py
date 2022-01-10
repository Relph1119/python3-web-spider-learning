#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: back_forward.py
@time: 2022/1/7 15:21
@project: python3-web-spider-learning
@desc: 前进和后退（P221）
"""
import time

from selenium import webdriver

browser = webdriver.Chrome()
browser.get('https://www.baidu.com/')
browser.get('https://www.taobao.com/')
browser.get('https://www.python.org')
browser.back()
time.sleep(1)
browser.forward()
browser.close()
