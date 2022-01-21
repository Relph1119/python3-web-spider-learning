#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: elasticsearch_oper_demo.py
@time: 2022/1/6 9:15
@project: python3-web-spider-learning
@desc: 4.7 Elasticsearch搜索引擎存储（P161~P166）
"""
from elasticsearch import Elasticsearch


def create_index():
    result = es.indices.create(index='news', ignore=400)
    print(result)


def delete_index():
    result = es.indices.delete(index='news', ignore=[400, 404])
    print(result)


def insert_data():
    es.indices.create(index='news', ignore=400)

    data = {
        'title': '乘风破浪不负韶华，奋斗青春圆梦高考',
        'url': 'http://view.indws.qq.com/a/EDU20210416007322200'
    }
    result = es.create(index='news', id=1, body=data)
    print(result)


def update_data():
    data = {
        'title': '乘风破浪不负韶华，奋斗青春圆梦高考',
        'url': 'http://view.indws.qq.com/a/EDU20210416007322200',
        'date': '2021-07-05'
    }
    result = es.update(index='news', body=data, id=1, ignore=400)
    print(result)


def delete_data():
    result = es.delete(index='news', id=1)
    print(result)


def select_data():
    mapping = {
        'properties': {
            'title': {
                'type': 'text',
                'analyzer': 'ik_max_word',
                'search_analyzer': 'ik_max_word'
            }
        }
    }
    es.indices.delete(index='news', ignore=[400, 404])
    es.indices.create(index='news', ignore=400)
    result = es.indices.put_mapping(index='news', body=mapping)
    print(result)

    datas = [
        {
            'title': '高考结局大不同',
            'url': 'https://k.sina.com.cn/article_7571064628_1c3454734001011lz9.html',
        },
        {
            'title': '进入职业大洗牌时代，“吃香”职业还吃香吗？',
            'url': 'https://new.qq.com/omn/20210828/20210828A025LK00.html',
        },
        {
            'title': '乘风破浪不负韶华，奋斗青春圆梦高考',
            'url': 'http://view.inews.qq.com/a/EDU2021041600732200',
        },
        {
            'title': '他，活出了我们理想的样子',
            'url': 'https://new.qq.com/omn/20210821/20210821A020ID00.html',
        }
    ]

    for data in datas:
        es.index(index='news', body=data)

    result = es.search(index='news')
    print(result)


def full_text_search():
    dsl = {
        'query': {
            'match': {
                'title': '高考 圆梦'
            }
        }
    }
    result = es.search(index='news', body=dsl)
    print(result)


if __name__ == '__main__':
    es = Elasticsearch()
    full_text_search()
