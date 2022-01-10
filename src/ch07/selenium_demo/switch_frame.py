#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: switch_frame.py
@time: 2022/1/7 10:41
@project: python3-web-spider-learning
@desc: 切换Frame（P219）
"""
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException

browser = webdriver.Chrome()
url = 'https://www.runoob.com/try/try.php?filename=jqueryui-api-droppable'
browser.get(url)
browser.switch_to.frame('iframeResult')
try:
    logo = browser.find_element_by_class_name('logo')
except NoSuchElementException:
    print('No Logo')

browser.switch_to.parent_frame()
logo = browser.find_element_by_class_name('logo')
print(logo)
print(logo.text)
