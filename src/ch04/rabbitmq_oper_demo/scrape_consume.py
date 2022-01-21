#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: scrape_consume.py
@time: 2022/1/6 15:10
@project: python3-web-spider-learning
@desc: RabbitMQ实战 消费者（P172）
"""
import pickle

import pika
import requests

MAX_PRORITY = 100
QUEUE_NAME = 'scrape_queue'

connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
channel = connection.channel()
session = requests.Session()


def scrape(request):
    try:
        response = session.send(request.prepare())
        print(f'success scraped {response.url}')
    except requests.RequestException:
        print(f'error occurred when scraping {request.url}')


while True:
    method_frame, header, body = channel.basic_get(queue=QUEUE_NAME, auto_ack=True)
    if body:
        request = pickle.loads(body)
        print(f'Get {request}')
        scrape(request)
