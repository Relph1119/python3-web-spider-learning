#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: tester.py
@time: 2022/1/12 10:46
@project: python3-web-spider-learning
@desc: 检测模块：检测失效Cookie，然后将其从Redis中删除
"""
from ch10.account_pool.exceptions import InitException
from ch10.account_pool.setting import *
from ch10.account_pool.storages_redis import RedisClient
from loguru import logger
import requests

class BaseTester:
    def __init__(self, website=None):
        self.website = website
        if not self.website:
            raise InitException
        self.account_operator = RedisClient(type='account', website=self.website)
        self.credential_operator = RedisClient(type='credential', website=self.website)

    def test(self, username, credential):
        raise NotImplementedError

    def run(self):
        credentials = self.credential_operator.all()
        for username, credential in credentials.items():
            self.test(username, credential)


class Antispider6Tester(BaseTester):
    def __init__(self, website=None):
        super().__init__(website)

    def test(self, username, credential):
        logger.info(f'testing credential for {username}')
        try:
            test_url = TEST_URL_MAP[self.website]
            response = requests.get(test_url, headers={
                'Cookie': credential
            }, timeout=TEST_TIMEOUT, allow_redirects=False)
            if response.status_code == 200:
                logger.info('credential is valid')
            else:
                logger.info('credential is not valid, delete it')
                self.credential_operator.delete(username)
        except Exception as e:
            logger.error(f'test failed: {e}')
            logger.info('credential is not valid, delete it')
            self.credential_operator.delete(username)