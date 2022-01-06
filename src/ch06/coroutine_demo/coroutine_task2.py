#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: coroutine_task2.py
@time: 2022/1/6 18:50
@project: python3-web-spider-learning
@desc: 协程task的使用（P195）
"""
import asyncio


async def execute(x):
    print('Number:', x)
    return x

coroutine = execute(1)
print('Coroutine:', coroutine)
print('After calling execute')

task = asyncio.ensure_future(coroutine)
print('Task:', task)
loop = asyncio.get_event_loop()
loop.run_until_complete(task)
print('Task:', task)
print('After calling loop')