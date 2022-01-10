#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: exception_handle.py
@time: 2022/1/7 15:35
@project: python3-web-spider-learning
@desc: 异常处理（P223）
"""
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, NoSuchElementException

browser = webdriver.Chrome()
try:
    browser.get('https://www.baidu.com')
except TimeoutException:
    print('Time Out')

try:
    browser.find_element_by_id('hello')
except NoSuchElementException:
    print('No Element')
finally:
    browser.close()
