#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: airtest_script.py
@time: 2022/1/16 2:45
@project: python3-web-spider-learning
@desc: 12.7 基于Airtest的App爬取实战（P586）
"""
import os

from airtest.core.api import stop_app, start_app, keyevent, swipe, connect_device
from itsdangerous import json
from loguru import logger
from poco.drivers.android.uiautomation import AndroidUiautomationPoco

poco = AndroidUiautomationPoco(use_airtest_input=True, screenshot_each_action=False)
window_width, window_height = poco.get_screen_size()
PACKAGE_NAME = "com.goldze.mvvmhabit"
TOTAL_NUMBER = 100


def scrape_index():
    elements = poco(f'{PACKAGE_NAME}:id/item')
    elements.wait_for_appearance()
    return elements


def scrape_detail(element):
    logger.debug(f'scraping {element}')
    element.click()
    panel = poco(f'{PACKAGE_NAME}:id/content')
    panel.wait_for_appearance()
    title = poco(f'{PACKAGE_NAME}:id/title').attr('text')
    categories = poco(f'{PACKAGE_NAME}:id/categories_value').attr('text')
    score = poco(f'{PACKAGE_NAME}:id/score_value').attr('text')
    published_at = poco(f'{PACKAGE_NAME}:id/published_at_value').attr('text')
    drama = poco(f'{PACKAGE_NAME}:id/drama_value').attr('text')
    keyevent('BACK')
    return {
        'title': title,
        'categories': categories,
        'score': score,
        'published_at': published_at,
        'drama': drama,
    }


def scroll_up():
    """
    上滑动操作
    """
    swipe((window_width * 0.5, window_height * 0.8),
          vertor=[0, -0.5], duration=1)


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
            element_title = element.offspring(f'{PACKAGE_NAME}:id/tv_title')
            if not element_title.exists():
                continue
            title = element_title.attr('text')
            logger.debug(f'get title {title}')
            if title in scraped_titles:
                continue
            _, element_y = element.get_position()
            if element_y > 0.7:
                scroll_up()
            element_data = scrape_detail(element)
            scraped_titles.append(title)
            logger.debug(f'scraped data {element_data}')


if __name__ == '__main__':
    connect_device("Android://127.0.0.1:5037/192.168.1.26:5555")
    stop_app(PACKAGE_NAME)
    start_app(PACKAGE_NAME)
    main()
