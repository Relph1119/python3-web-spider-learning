#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: mobile_web.py
@time: 2022/1/10 19:48
@project: python3-web-spider-learning
@desc: 支持移动端浏览器（P261）
"""
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    iphone_12_pro_max = p.devices['iPhone 12 Pro Max']
    browser = p.webkit.launch(headless=False)
    context = browser.new_context(**iphone_12_pro_max, locale='zh-CN')
    page = context.new_page()
    page.goto('https://www.whatismybrowser.com')
    page.wait_for_load_state(state='networkidle')
    page.screenshot(path='files/browser-iphone.png')
    browser.close()
