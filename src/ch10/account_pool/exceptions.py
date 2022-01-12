#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: exceptions.py
@time: 2022/1/12 10:36
@project: python3-web-spider-learning
@desc: 自定义异常
"""


class InitException(Exception):
    def __str__(self):
        """
        init error
        :return:
        """
        return repr('init failed')
