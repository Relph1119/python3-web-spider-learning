#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: scrape_producer.py
@time: 2022/1/6 15:10
@project: python3-web-spider-learning
@desc: RabbitMQ实战 生产者（P171）
"""
import pickle

import pika
import requests

MAX_PRORITY = 100
TOTAL = 100
QUEUE_NAME = 'scrape_queue'

connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
channel = connection.channel()
channel.queue_declare(queue=QUEUE_NAME, durable=True)

for i in range(1, TOTAL + 1):
    url = f'http://ssr1.scrape.center/detail/{i}'
    request = requests.Request('GET', url)
    channel.basic_publish(exchange='', routing_key=QUEUE_NAME,
                          properties=pika.BasicProperties(delivery_mode=2),
                          body=pickle.dumps(request))
    print(f'Put request of {url}')
