#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: delay_wait.py
@time: 2022/1/7 15:05
@project: python3-web-spider-learning
@desc: 延时等待（P220）
"""
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def implicit_wait():
    browser = webdriver.Chrome()
    browser.implicitly_wait(10)
    browser.get('https://spa2.scrape.center/')
    input = browser.find_element_by_class_name('logo-image')
    print(input)


def explicit_wait():
    browser = webdriver.Chrome()
    browser.get('https://www.taobao.com/')
    wait = WebDriverWait(browser, 10)
    input = wait.until(EC.presence_of_element_located((By.ID, 'q')))
    button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, '.btn-search')))
    print(input, button)


if __name__ == '__main__':
    explicit_wait()
