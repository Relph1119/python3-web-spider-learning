#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: appium_scrape_practice.py
@time: 2022/1/16 2:45
@project: python3-web-spider-learning
@desc: 12.5 基于Appium的App爬取实战（P562）
目标App：app5-scrape.apk
爬取流程：
（1）遍历现有的电影条目，依次模拟点击每个电影条目，进入详情页
（2）爬取详情页的数据，爬取完毕后，模拟点击回退操作，返回首页
（3）当首页的所有电影条目爬取完毕，模拟上滑动操作，加载更多电影
（4）在爬取过程中，将爬取到的数据记录下来，避免重复爬取
（5）所有数据爬取完毕后，终止爬取
"""
import json
import os

from appium import webdriver
from loguru import logger
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

SERVER = 'http://localhost:4723/wd/hub'
DESIRED_CAPABILITIS = {
    "platformName": "Android",
    "appium:deviceName": "VirtualBox",
    "appium:appPackage": "com.goldze.mvvmhabit",
    "appium:appActivity": "com.goldze.mvvmhabit.ui.MainActivity",
    "appium:noReset": True
}
PACKAGE_NAME = DESIRED_CAPABILITIS['appium:appPackage']
TOTAL_NUMBER = 100

# 启动示例App
driver = webdriver.Remote(SERVER, DESIRED_CAPABILITIS)
wait = WebDriverWait(driver, 30)
window_size = driver.get_window_size()
window_width, window_height = window_size.get('width'), window_size.get('height')


def scrape_index():
    """
    获取首页上的所有电影条目
    """
    items = wait.until(EC.presence_of_all_elements_located(
        (By.XPATH, f'//android.widget.LinearLayout[@resource-id="{PACKAGE_NAME}:id/item"]')))
    return items


def scrape_detail(element):
    """
    获取详情页数据
    """
    logger.debug(f'scraping {element}')
    element.click()
    wait.until(EC.presence_of_element_located(
        (By.ID, f'{PACKAGE_NAME}:id/detail')))
    title = wait.until(EC.presence_of_element_located(
        (By.ID, f'{PACKAGE_NAME}:id/title'))).get_attribute('text')
    categories = wait.until(EC.presence_of_element_located(
        (By.ID, f'{PACKAGE_NAME}:id/categories_value'))).get_attribute('text')
    score = wait.until(EC.presence_of_element_located(
        (By.ID, f'{PACKAGE_NAME}:id/score_value'))).get_attribute('text')
    minute = wait.until(EC.presence_of_element_located(
        (By.ID, f'{PACKAGE_NAME}:id/minute_value'))).get_attribute('text')
    published_at = wait.until(EC.presence_of_element_located(
        (By.ID, f'{PACKAGE_NAME}:id/published_at_value'))).get_attribute('text')
    drama = wait.until(EC.presence_of_element_located(
        (By.ID, f'{PACKAGE_NAME}:id/drama_value'))).get_attribute('text')
    driver.back()
    return {
        'title': title,
        'categories': categories,
        'score': score,
        'minute': minute,
        'published_at': published_at,
        'drama': drama,
    }


def scroll_up():
    """
    上滑动操作
    """
    driver.swipe(window_width * 0.5, window_height * 0.8,
                 window_width * 0.5, window_height * 0.2, 1000)


def get_element_title(element):
    """
    得到title数据
    """
    try:
        element_title = element.find_element_by_id(f'{PACKAGE_NAME}:id/tv_title').get_attribute('text')
        return element_title
    except NoSuchElementException:
        return None


OUTPUT_FOLDER = 'movie'
os.path.exists(OUTPUT_FOLDER) or os.makedirs(OUTPUT_FOLDER)


def save_data(element_data):
    """
    保存数据
    """
    with open(f'{OUTPUT_FOLDER}/{element_data.get("title")}.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(element_data, ensure_ascii=False, indent=2))
        logger.debug(f'saved as file {element_data.get("title")}.json')


def main():
    scraped_titles = []
    while len(scraped_titles) < TOTAL_NUMBER:
        elements = scrape_index()
        for element in elements:
            element_title = get_element_title(element)
            if not element_title or element_title in scraped_titles:
                continue
            element_location = element.location
            element_y = element_location.get('y')
            if element_y / window_height > 0.8:
                logger.debug(f'scroll up')
                scroll_up()
            element_data = scrape_detail(element)
            scraped_titles.append(element_title)
            logger.debug(f'scraped data {element_data}')
            save_data(element_data)


if __name__ == '__main__':
    main()
