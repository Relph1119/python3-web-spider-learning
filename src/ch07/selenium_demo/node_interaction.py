#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: node_interaction.py
@time: 2022/1/7 10:20
@project: python3-web-spider-learning
@desc: 节点交互（P216）
"""
import time

from selenium import webdriver

browser = webdriver.Chrome()
browser.get('https://www.taobao.com')
# 得到搜索框
input = browser.find_element_by_id('q')
# 输入搜索词“iPhone”
input.send_keys('iPhone')
time.sleep(1)
# 清空搜索框
input.clear()
# 输入搜索词“iPad”
input.send_keys('iPad')
# 得到搜索按钮
button = browser.find_element_by_class_name('btn-search')
# 点击搜索按钮
button.click()
