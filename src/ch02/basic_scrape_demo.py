#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: basic_scrape_demo.py
@time: 2022/1/4 14:20
@project: python3-web-spider-learning
@desc: 2.5 基础爬虫案例实战（P78~P89）
"""
import json
import logging
import multiprocessing
import os
import re
import shutil
from urllib.parse import urljoin

import requests

# 定义日志输出级别和输出格式
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

BASE_URL = 'https://ssr1.scrape.center'
TOTAL_PAGE = 10


def scrape_page(url):
    """页面爬取
    """
    logging.info('scraping %s...', url)
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        logging.error('get invalid status code %s while scraping %s', response.status_code, url)
    except requests.RequestException:
        logging.error('error occurred while scraping %s', url, exc_info=True)


def scrape_index(page):
    """
    爬取列表页
    """
    index_url = f'{BASE_URL}/page/{page}'
    return scrape_page(index_url)


def parse_index(html):
    """
    获取每部电影的详情页URL
    """
    # <a data-v-7f856186="" href="/detail/11" class="name">
    pattern = re.compile('<a.*?href="(.*?)".*?class="name">')
    items = re.findall(pattern, html)
    if not items:
        return []

    for item in items:
        detail_url = urljoin(BASE_URL, item)
        logging.info('get detail url %s', detail_url)
        yield detail_url


def scrape_detail(url):
    """
    爬取详情页
    """
    return scrape_page(url)


def parse_detail(html) -> dict:
    """解析详情页
    """
    # <div data-v-63864230="" class="item el-row">
    #     <div data-v-63864230="" class="el-col el-col-24 el-col-xs-0 el-col-sm-8">
    #       <a data-v-63864230="" class="router-link-exact-active router-link-active">
    #         <img data-v-63864230="" src="https://p0.meituan.net/movie/ce4da3e03e655b5b88ed31b5cd7896cf62472.jpg
    #         @464w_644h_1e_1c" class="cover">
    #       </a>
    #     </div>
    #   </div>
    cover_pattern = re.compile('class="item.*?<img.*?src="(.*?)".*?class="cover">', re.S)

    # <h2 data-v-63864230="" class="m-b-sm">霸王别姬 - Farewell My Concubine</h2>
    name_pattern = re.compile('<h2.*?>(.*?)</h2>')

    #   <button data-v-7f856186="" type="button" class="el-button category el-button--primary el-button--mini">
    #     <span>剧情</span>
    #   </button>
    #
    #   <button data-v-7f856186="" type="button" class="el-button category el-button--primary el-button--mini">
    #     <span>爱情</span>
    #   </button>
    categories_pattern = re.compile('<button.*?category.*?<span>(.*?)</span>.*?</button>', re.S)

    # <span data-v-7f856186="">1993-07-26 上映</span>
    published_at_pattern = re.compile('(\d{4}-\d{2}-\d{2})\s?上映')

    # <div data-v-63864230="" class="drama"><h3 data-v-63864230="">剧情简介</h3>
    #    <p data-v-63864230="">
    #      影片借一出《霸王别姬》的京戏，牵扯出三个人之间一段随时代风云变幻的爱恨情仇。段小楼（张丰毅 饰）与程蝶衣（张国荣 饰）是一对打小一起长大的
    #      师兄弟，两人一个演生，一个饰旦，一向配合天衣无缝，尤其一出《霸王别姬》，更是誉满京城，为此，两人约定合演一辈子《霸王别姬》。但两人对戏剧
    #      与人生关系的理解有本质不同，段小楼深知戏非人生，程蝶衣则是人戏不分。段小楼在认为该成家立业之时迎娶了名妓菊仙（巩俐 饰），致使程蝶衣认定
    #      菊仙是可耻的第三者，使段小楼做了叛徒，自此，三人围绕一出《霸王别姬》生出的爱恨情仇战开始随着时代风云的变迁不断升级，终酿成悲剧。
    #    </p>
    # </div>
    drama_pattern = re.compile('<div.*?drama.*?>.*?<p.*?>(.*?)</p>', re.S)

    # <p data-v-63864230="" class="score m-t-md m-b-n-sm">9.5</p>
    score_pattern = re.compile('<p.*?score.*?>(.*?)</p>', re.S)

    cover = re.search(cover_pattern, html).group(1).strip() if re.search(cover_pattern, html) else None
    name = re.search(name_pattern, html).group(1).strip() if re.search(name_pattern, html) else None
    categories = re.findall(categories_pattern, html) if re.findall(categories_pattern, html) else []
    published_at = re.search(published_at_pattern, html).group(1) if re.search(published_at_pattern, html) else None
    drama = re.search(drama_pattern, html).group(1).strip() if re.search(drama_pattern, html) else None
    score = float(re.search(score_pattern, html).group(1).strip()) if re.search(score_pattern, html) else None

    return {
        'cover': cover,
        'name': name,
        'categories': categories,
        'published_at': published_at,
        'drama': drama,
        'score': score
    }


RESULT_DIR = 'film_results'
if os.path.exists(RESULT_DIR):
    shutil.rmtree(RESULT_DIR)
os.makedirs(RESULT_DIR)


def save_data(data: dict):
    # 保存数据为json格式
    name = data.get('name')
    data_path = f'{RESULT_DIR}/{name}.json'
    json.dump(data, open(data_path, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)


def main(page):
    index_html = scrape_index(page)
    detail_urls = parse_index(index_html)
    for detail_url in detail_urls:
        detail_html = scrape_detail(detail_url)
        data = parse_detail(detail_html)
        logging.info('get detail data %s', data)
        logging.info('saving data to json file')
        save_data(data)
        logging.info('data saved successfully')


if __name__ == '__main__':
    # 采用多进程加速
    pool = multiprocessing.Pool()
    pages = range(1, TOTAL_PAGE + 1)
    pool.map(main, pages)
    pool.close()
    pool.join()
