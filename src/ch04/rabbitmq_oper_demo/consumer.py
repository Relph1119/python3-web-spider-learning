#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: consumer.py
@time: 2022/1/6 14:32
@project: python3-web-spider-learning
@desc: RabbitMQ 消费者示例（P167）
"""
import pika

MAX_PRIORITY = 100
QUEUE_NAME = 'scrape'
connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()


def callback(ch, method, properties, body):
    print(f'Get {body}')


def simple_consume():
    channel.queue_declare(queue=QUEUE_NAME)
    channel.basic_consume(queue=QUEUE_NAME, auto_ack=True, on_message_callback=callback)
    channel.start_consuming()


def on_demand_consume():
    channel.queue_declare(queue=QUEUE_NAME)
    while True:
        input()
        method_frame, header, body = channel.basic_get(queue=QUEUE_NAME, auto_ack=True)
        if body:
            print(f'Get {body}')


def priority_consume():
    channel.queue_declare(queue=QUEUE_NAME, arguments={
        'x-max-priority': MAX_PRIORITY
    })

    while True:
        input()
        method_frame, header, body = channel.basic_get(queue=QUEUE_NAME, auto_ack=True)
        if body:
            print(f'Get {body}')


def persistence_consume():
    channel.queue_declare(queue=QUEUE_NAME, arguments={
        'x-max-priority': MAX_PRIORITY
    }, durable=True)

    while True:
        input()
        method_frame, header, body = channel.basic_get(queue=QUEUE_NAME, auto_ack=True)
        if body:
            print(f'Get {body}')


if __name__ == '__main__':
    on_demand_consume()
