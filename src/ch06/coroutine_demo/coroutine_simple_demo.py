#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: coroutine_simple_demo.py
@time: 2022/1/6 17:23
@project: python3-web-spider-learning
@desc: 定义协程（P194）
"""
import asyncio


async def execute(x):
    print('Number:', x)

coroutine = execute(1)
print('Coroutine:', coroutine)
print('After calling execute')

loop = asyncio.get_event_loop()
# 将协程对象注册到事件循环上
loop.run_until_complete(coroutine)
print('After calling loop')
