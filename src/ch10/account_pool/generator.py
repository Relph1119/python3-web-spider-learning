#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: processors_generator.py
@time: 2022/1/12 10:34
@project: python3-web-spider-learning
@desc: 获取模块，主要负责从存储模块中拿取各个账号信息，并模拟登录，将登录成功后生产的Cookie保存到存储模块中
"""

import requests
from loguru import logger

from ch10.account_pool.exceptions import InitException
from ch10.account_pool.storages_redis import RedisClient


class BaseGenerator:
    def __init__(self, website=None):
        self.website = website
        if not self.website:
            raise InitException
        self.account_operator = RedisClient(type='account', website=self.website)
        self.credential_operator = RedisClient(type='credential', website=self.website)

    def generate(self, username, password):
        raise NotImplementedError

    def init(self):
        pass

    def run(self):
        self.init()
        logger.debug('start to run generator')
        for username, password in self.account_operator.all().items():
            if self.credential_operator.get(username):
                continue
            logger.debug(f'start to generator credential of {username}')
            self.generate(username, password)


class Antispider6Generator(BaseGenerator):
    def generate(self, username, password):
        if self.credential_operator.get(username):
            logger.debug(f'credential of {username} exists, skip')
            return
        login_url = 'https://antispider6.scrape.center/login'
        s = requests.Session()
        try:
            s.post(login_url, data={
                'username': username,
                'password': password
            })
            result = []
            for cookie in s.cookies:
                print(cookie.name, cookie.value)
                result.append(f'{cookie.name}={cookie.value}')
            result = ';'.join(result)
            if len(result) > 0:
                logger.debug(f'get {username} credential {result}')
                self.credential_operator.set(username, result)
        except Exception as e:
            logger.error(f'get {username} credential failed: {e}')
