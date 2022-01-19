#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: extensions.py
@time: 2022/1/19 18:43
@project: python3-web-spider-learning
@desc: 
"""
import requests
from scrapy import signals

NOTIFICATION_URL = 'http://localhost:5000/notify'


class NotificationExtension:
    def spider_opend(self, spider):
        requests.post(NOTIFICATION_URL, json={
            'event': 'SPIDER_OPENED',
            'data': {'spider_name': spider.name}
        })

    def spider_closed(self, spider):
        requests.post(NOTIFICATION_URL, json={
            'event': 'SPIDER_CLOSED',
            'data': {'spider_name': spider.name}
        })

    def item_scraped(self, item, spider):
        requests.post(NOTIFICATION_URL, json={
            'event': 'ITEM_SCRAPED',
            'data': {'spider_name': spider.name, 'item': dict(item)}
        })

    @classmethod
    def from_crawler(cls, crawler):
        ext = cls()
        crawler.signals.connect(ext.spider_opend, signal=signals.spider_opened)
        crawler.signals.connect(ext.spider_closed, signal=signals.spider_closed)
        crawler.signals.connect(ext.item_scraped, signal=signals.item_scraped)
        return ext
