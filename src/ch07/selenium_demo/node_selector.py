#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: node_selector.py
@time: 2022/1/7 10:04
@project: python3-web-spider-learning
@desc: 查找节点（P215-P216）
"""
from selenium import webdriver

browser = webdriver.Chrome()
browser.get('https://www.taobao.com')


def get_signal_node():
    input_first = browser.find_element_by_id('q')
    input_second = browser.find_element_by_css_selector('#q')
    input_third = browser.find_element_by_xpath('//*[@id="q"]')
    print(input_first, input_second, input_third)


def get_nodes():
    lis = browser.find_elements_by_css_selector('.service-bd li')
    print(lis)


if __name__ == '__main__':
    get_nodes()
    browser.close()
