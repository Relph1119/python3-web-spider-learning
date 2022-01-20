#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: run.py
@time: 2022/1/20 11:29
@project: python3-web-spider-learning
@desc: 15.12 Scrapy规则化爬虫（实战，P818）
"""
import argparse

from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings

from ch15.scrapyuniversaldemo.scrapyuniversaldemo.utils import get_config

parser = argparse.ArgumentParser(description='Universal Spider')
parser.add_argument('name', help='name of spider to run')
args = parser.parse_args()
name = args.name


def run():
    config = get_config(name)
    spider = config.get('spider', 'universal')
    project_settings = get_project_settings()
    settings = dict(project_settings.copy())
    settings.update(config.get('settings'))
    process = CrawlerProcess(settings)
    process.crawl(spider, **{'name': name})
    process.start()


if __name__ == '__main__':
    run()
