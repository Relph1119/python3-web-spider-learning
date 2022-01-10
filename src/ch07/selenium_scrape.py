#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: selenium_scrape.py
@time: 2022/1/10 20:16
@project: python3-web-spider-learning
@desc: 7.5 Selenium爬取实战（P269）
难点：
（1）详情页的URL看上去由Base64生成，参数被加密了
（2）接口中token字段每次访问不一样
思路：
采用selennium绕过ajax，直接过去JavaScript最终渲染的页面源代码，从中提取数据
"""
import json
import os
from urllib.parse import urljoin

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC

import logging

from selenium.webdriver.support.wait import WebDriverWait

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

INDEX_URL = 'https://spa2.scrape.center/page/{page}'
TIME_OUT = 10
TOTAL_PAGE = 10

browser = webdriver.Chrome()
wait = WebDriverWait(browser, TIME_OUT)


def scrape_page(url, condition, locator):
    """
    爬取网页
    """
    logging.info('scraping %s', url)
    try:
        browser.get(url)
        wait.until(condition(locator))
    except TimeoutException:
        logging.error('error occurred while scraping %s', url, exc_info=True)


def scrape_index(page):
    """
    爬取列表页
    """
    url = INDEX_URL.format(page=page)
    # 当所有节点都加载出来，才算成功
    scrape_page(url, condition=EC.visibility_of_element_located, locator=(By.CSS_SELECTOR, '#index .item'))


def parse_index():
    # 获取所有电影节点
    elements = browser.find_elements_by_css_selector('#index .item .name')
    for element in elements:
        # 得到详情页的href属性
        href = element.get_attribute('href')
        # 拼接成完整的详情页地址
        yield urljoin(INDEX_URL, href)


def scrape_detail(url):
    # 传入电影的名称节点
    scrape_page(url, condition=EC.visibility_of_element_located,
                locator=(By.TAG_NAME, 'h2'))


def parse_detail() -> dict:
    url = browser.current_url
    # 名称
    name = browser.find_element_by_tag_name('h2').text
    # 类别
    categories = [element.text for element in browser.find_elements_by_css_selector('.categories button span')]
    # 封面
    cover = browser.find_element_by_css_selector('.cover').get_attribute('src')
    # 评分
    score = browser.find_element_by_class_name('score').text
    # 简介
    drama = browser.find_element_by_css_selector('.drama p').text

    return {
        'url': url,
        'name': name,
        'categories': categories,
        'cover': cover,
        'score': score,
        'drama': drama
    }


RESULT_DIR = 'results'

if not os.path.exists(RESULT_DIR):
    os.makedirs(RESULT_DIR)


def save_data(data):
    """
    保存数据
    """
    name = data.get('name')
    data_path = f'{RESULT_DIR}/{name}.json'
    json.dump(data, open(data_path, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)


def main():
    try:
        for page in range(1, TOTAL_PAGE + 1):
            scrape_index(page)
            detail_urls = parse_index()
            for detail_url in list(detail_urls):
                scrape_detail(detail_url)
                detail_data = parse_detail()
                logging.info('detail data %s', detail_data)
                logging.info('saving data to json file')
                save_data(detail_data)
                logging.info('data saved successfully')
    finally:
        browser.close()


if __name__ == '__main__':
    main()
