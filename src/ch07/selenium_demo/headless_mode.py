#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: headless_mode.py
@time: 2022/1/7 15:49
@project: python3-web-spider-learning
@desc: 无头模式（P225）
"""
from selenium import webdriver
from selenium.webdriver import ChromeOptions
import os

option = ChromeOptions()
option.add_argument('--headless')
browser = webdriver.Chrome(options=option)
browser.set_window_size(1366, 768)
browser.get('https://www.baidu.com')

if not os.path.exists('files'):
    os.makedirs('files')

browser.get_screenshot_as_file('files/preview.png')
