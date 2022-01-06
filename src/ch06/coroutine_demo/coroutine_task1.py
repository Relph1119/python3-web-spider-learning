#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: coroutine_task1.py
@time: 2022/1/6 17:31
@project: python3-web-spider-learning
@desc: 协程task的使用（P194）
"""
import asyncio


async def execute(x):
    print('Number:', x)
    return x

coroutine = execute(1)
print('Coroutine:', coroutine)
print('After calling execute')

loop = asyncio.get_event_loop()
task = loop.create_task(coroutine)
print('Task:', task)
loop.run_until_complete(task)
print('Task:', task)
print('After calling loop')