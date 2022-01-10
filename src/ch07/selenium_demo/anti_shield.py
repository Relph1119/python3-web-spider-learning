#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: anti_shield.py
@time: 2022/1/7 15:40
@project: python3-web-spider-learning
@desc: 反屏蔽（P224）
"""
from selenium import webdriver
from selenium.webdriver import ChromeOptions

option = ChromeOptions()
option.add_experimental_option('excludeSwitches', ['enable-automation'])
option.add_experimental_option('useAutomationExtension', False)
browser = webdriver.Chrome(options=option)
browser.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
    'source': 'Object.defineProperty(navigator, "webdriver", {get: () => undefined})'
})
browser.get('https://antispider1.scrape.center')

