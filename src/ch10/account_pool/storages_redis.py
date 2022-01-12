#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: storages_redis.py
@time: 2022/1/12 10:18
@project: python3-web-spider-learning
@desc: 存储模块：使用Redis作为账号池的存储库，数据结构如下：
<user_name>: <password>
<user_name>: <cookie_value>
"""
import random

from ch10.account_pool.setting import *
import redis


class RedisClient:
    def __init__(self, type, website, host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD):
        self.db = redis.StrictRedis(host=host, port=port, password=password, decode_responses=True)
        # 网站类型
        self.type = type
        # 网站名称
        self.website = website

    def name(self):
        return f'{self.type}:{self.website}'

    def set(self, username, value):
        return self.db.hset(self.name(), username, value)

    def get(self, username):
        return self.db.hget(self.name(), username)

    def delete(self, username):
        return self.db.hdel(self.name(), username)

    def count(self):
        return self.db.hlen(self.name())

    def random(self):
        # 随机选择一个cookie
        return random.choice(self.db.hvals(self.name()))

    def usernames(self):
        return self.db.hkeys(self.name())

    def all(self):
        return self.db.hgetall(self.name())

    def close(self):
        self.db.close()