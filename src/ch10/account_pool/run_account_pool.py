#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: run_account_pool.py
@time: 2022/1/12 14:27
@project: python3-web-spider-learning
@desc: 运行账号池
"""
from ch10.account_pool.setting import ENABLE_IMPORT_DATA
from ch10.account_pool.storages_redis import RedisClient
from scheduler import Scheduler
import argparse

parser = argparse.ArgumentParser(description='AccountPool')
parser.add_argument('website', type=str, help='website')
parser.add_argument('--processor', type=str, help='processor to run')
args = parser.parse_args()
website = args.website

if __name__ == '__main__':
    if ENABLE_IMPORT_DATA:
        conn = RedisClient('account', website)
        start = 1
        end = 20
        for i in range(start, end + 1):
            username = password = f'admin{i}'
            conn.set(username, password)
        conn.close()

    # if processor set, just run it
    if args.processor:
        getattr(Scheduler(), f'run_{args.processor}')(website)
    else:
        Scheduler().run(website)
