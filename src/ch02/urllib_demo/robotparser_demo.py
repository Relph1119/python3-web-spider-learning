#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: robotparser_demo.py
@time: 2021/12/31 13:39
@project: python3-web-spider-learning
@desc: Robots协议（P46）
"""

from urllib.robotparser import RobotFileParser


def print_can_fetch(rp, spider, url):
    print(rp.can_fetch(spider, url))


if __name__ == '__main__':
    rp = RobotFileParser()
    rp.set_url('https://www.baidu.com/robots.txt')
    rp.read()
    print_can_fetch(rp, 'Baiduspider', 'https://www.baidu.com')
    print_can_fetch(rp, 'Baiduspider', 'https://www.baidu.com/homepage/')
    print_can_fetch(rp, 'Googlebot', 'https://www.baidu.com/homepage/')
