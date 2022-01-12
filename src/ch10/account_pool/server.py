#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: server.py
@time: 2022/1/12 14:00
@project: python3-web-spider-learning
@desc: 
"""
from flask import Flask, g

from ch10.account_pool.setting import GENERATOR_MAP
from ch10.account_pool.storages_redis import RedisClient
from loguru import logger

app = Flask(__name__)

account = 'account'
credential = 'credential'


@app.route('/')
def index():
    return '<h2>Welcome to Cookie Pool System</h2>'


def get_conn():
    for website in GENERATOR_MAP:
        if not hasattr(g, website):
            setattr(g, f'{website}_{credential}', RedisClient(credential, website))
            setattr(g, f'{website}_{account}', RedisClient(account, website))
    return g


@app.route('/<website>/random')
def random(website):
    g = get_conn()
    result = getattr(g, f'{website}_{credential}').random()
    logger.debug(f'get credential {result}')
    return result
