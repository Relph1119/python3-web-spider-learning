#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: event_listen.py
@time: 2022/1/10 19:56
@project: python3-web-spider-learning
@desc: 事件监听（P263）
"""
import re

from playwright.sync_api import sync_playwright


def sync_on_response(response):
    # 打印请求和响应
    # print(f'Statue{response.status}: {response.url}')

    if '/api/movie/' in response.url and response.status == 200:
        print(response.json())


def sync():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        page.on('response', sync_on_response)
        page.goto('https://spa6.scrape.center/')
        page.wait_for_load_state('networkidle')
        browser.close()


def get_web_source():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        page.goto('https://spa6.scrape.center/')
        page.wait_for_load_state('networkidle')
        html = page.content()
        print(html)
        browser.close()


def get_node_attr():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        page.goto('https://spa6.scrape.center/')
        page.wait_for_load_state('networkidle')
        href = page.get_attribute('a.name', 'href')
        print(href)
        browser.close()


def get_node_attrs():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        page.goto('https://spa6.scrape.center/')
        page.wait_for_load_state('networkidle')
        elements = page.query_selector_all('a.name')
        for element in elements:
            print(element.get_attribute('href'))
            print(element.text_content())
        browser.close()


def get_node():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        page.goto('https://spa6.scrape.center/')
        page.wait_for_load_state('networkidle')
        element = page.query_selector('a.name')
        print(element.get_attribute('href'))
        print(element.text_content())
        browser.close()


def route_demo():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()

        def cancel_request(route, request):
            route.abort()

        page.route(re.compile(r"(\.png)|(\.jpg)"), cancel_request)
        page.goto("https://spa6.scrape.center/")
        page.wait_for_load_state('networkidle')
        page.screenshot(path='files/np_picture.png')
        browser.close()


if __name__ == '__main__':
    route_demo()
