#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: scrape_ajax.py
@time: 2022/1/6 15:46
@project: python3-web-spider-learning
@desc: 5.3 Ajax分析与爬取实战（P184~P190）
"""
import logging

import pymongo
import requests

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s: %(message)s')

INDEX_URL = 'https://spa1.scrape.center/api/movie/?limit={limit}&offset={offset}'


def scrape_api(url):
    """
    爬取详情页
    """
    logging.info('scraping %s...', url)
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        logging.error('get invalid status code %s while scraping %s', response.status_code, url)
    except requests.RequestException:
        logging.error('error occurred while scraping %s', url, exc_info=True)


LIMIT = 10


def scrape_index(page):
    """
    爬取列表页
    """
    url = INDEX_URL.format(limit=LIMIT, offset=LIMIT * (page - 1))
    return scrape_api(url)


DETAIL_URL = 'https://spa1.scrape.center/api/movie/{id}'


def scrape_detail(id):
    """
    爬取详情页
    """
    url = DETAIL_URL.format(id=id)
    return scrape_api(url)


TOTAL_PAGE = 10
MONGO_CONNETCTION_STRING = 'mongodb://localhost:27017'
MONGO_DB_NAME = 'movies'
MONGO_COLLECTION_NAME = 'movies'

client = pymongo.MongoClient(MONGO_CONNETCTION_STRING)
db = client[MONGO_DB_NAME]
collection = db[MONGO_COLLECTION_NAME]


def save_data(data):
    collection.update_one({
        'name': data.get('name')
    }, {'$set': data}, upsert=True)


def main():
    for page in range(1, TOTAL_PAGE + 1):
        index_data = scrape_index(page)
        for item in index_data.get('results'):
            id = item.get('id')
            detail_data = scrape_detail(id)
            logging.info('detail data %s', detail_data)
            save_data(detail_data)
            logging.info('data saved successfully')


if __name__ == '__main__':
    main()
