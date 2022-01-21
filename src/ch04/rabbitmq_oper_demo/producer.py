#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: producer.py
@time: 2022/1/6 14:32
@project: python3-web-spider-learning
@desc: RabbitMQ 生产者示例（P169）
"""
import pika

MAX_PRIORITY = 100
QUEUE_NAME = 'scrape'
connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()


def simple_producer():
    channel.queue_declare(queue=QUEUE_NAME)
    channel.basic_publish(exchange='', routing_key=QUEUE_NAME, body='Hello World!')


def on_demand_producer():
    channel.queue_declare(queue=QUEUE_NAME)
    while True:
        data = input()
        channel.basic_publish(exchange='', routing_key=QUEUE_NAME, body=data)
        print(f'Put {data}')


def priority_producer():
    channel.queue_declare(queue=QUEUE_NAME, arguments={
        'x-max-priority': MAX_PRIORITY
    })

    while True:
        data, priority = input().split()
        channel.basic_publish(exchange='', routing_key=QUEUE_NAME,
                              properties=pika.BasicProperties(priority=int(priority)),
                              body=data)
        print(f'Put {data}')


def persistence_producer():
    channel.queue_declare(queue=QUEUE_NAME, arguments={
        'x-max-priority': MAX_PRIORITY
    }, durable=True)

    while True:
        data, priority = input().split()
        channel.basic_publish(exchange='', routing_key=QUEUE_NAME,
                              properties=pika.BasicProperties(
                                  priority=int(priority),
                                  delivery_mode=2
                              ),
                              body=data)
        print(f'Put {data}')


if __name__ == '__main__':
    priority_producer()
