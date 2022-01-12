#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: session_cookie_simulate_login.py
@time: 2022/1/12 9:12
@project: python3-web-spider-learning
@desc: 10.2 基于Session和Cookie的模拟登录爬取实战（P376）
"""
import time
from urllib.parse import urljoin
import requests
from selenium import webdriver

BASE_URL = 'https://login2.scrape.center/'
LOGIN_URL = urljoin(BASE_URL, '/login')
INDEX_URL = urljoin(BASE_URL, '/page/1')
USERNAME = 'admin'
PASSWORD = 'admin'


def simul_login_with_cookies():
    # 登录网站
    response_login = requests.post(LOGIN_URL, data={
        'username': USERNAME,
        'password': PASSWORD
    }, allow_redirects=False)

    # 保存Cookie
    cookies = response_login.cookies
    print('Cookies:', cookies)

    # 携带cookies访问列表页
    response_index = requests.get(INDEX_URL, cookies=cookies)
    print('Response Status', response_index.status_code)
    print('Response URL', response_index.url)


def simul_login_with_session():
    session = requests.Session()

    # 登录网站
    response_login = session.post(LOGIN_URL, data={
        'username': USERNAME,
        'password': PASSWORD
    })

    # 保存Cookie
    cookies = session.cookies
    print('Cookies:', cookies)

    # 携带cookies访问列表页
    response_index = session.get(INDEX_URL)
    print('Response Status', response_index.status_code)
    print('Response URL', response_index.url)


def simul_login_with_selenium():
    browser = webdriver.Chrome()
    browser.get(BASE_URL)
    browser.find_element_by_css_selector('input[name="username"]').send_keys(USERNAME)
    browser.find_element_by_css_selector('input[name="password"]').send_keys(PASSWORD)
    browser.find_element_by_css_selector('input[type="submit"]').click()
    time.sleep(10)

    # 从浏览器对象中获取Cookie信息
    cookies = browser.get_cookies()
    print('Cookies:', cookies)
    browser.close()

    # 把Cookies信息放入请求中
    session = requests.Session()
    for cookie in cookies:
        session.cookies.set(cookie['name'], cookie['value'])

    response_index = session.get(INDEX_URL)
    print('Response Status', response_index.status_code)
    print('Response URL', response_index.url)


if __name__ == '__main__':
    simul_login_with_selenium()
