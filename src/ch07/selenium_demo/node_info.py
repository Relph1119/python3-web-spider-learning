#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: node_info.py
@time: 2022/1/7 10:36
@project: python3-web-spider-learning
@desc: 获取节点信息（P218）
"""
from selenium import webdriver

browser = webdriver.Chrome()
url = 'https://spa2.scrape.center/'
browser.get(url)


def get_attr():
    logo = browser.find_element_by_class_name('logo-image')
    print(logo)
    print(logo.get_attribute('src'))


def get_text():
    input = browser.find_element_by_class_name('logo-title')
    print(input.text)


def get_other_info():
    input = browser.find_element_by_class_name('logo-title')
    print(input.id)
    print(input.location)
    print(input.tag_name)
    print(input.size)


if __name__ == '__main__':
    get_other_info()
