#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: action_chain.py
@time: 2022/1/7 10:25
@project: python3-web-spider-learning
@desc: 动作链（P217）
"""
from selenium import webdriver
from selenium.webdriver import ActionChains

browser = webdriver.Chrome()
url = 'http://www.runoob.com/try/try.php?filename=jqueryui-api-droppable'
browser.get(url)
browser.switch_to.frame('iframeResult')
source = browser.find_element_by_css_selector('#draggable')
target = browser.find_element_by_css_selector('#droppable')
actions = ActionChains(browser)
actions.drag_and_drop(source, target)
actions.perform()
