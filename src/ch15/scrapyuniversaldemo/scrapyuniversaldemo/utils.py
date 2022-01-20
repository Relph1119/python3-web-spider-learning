#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: utils.py
@time: 2022/1/20 15:52
@project: python3-web-spider-learning
@desc: 
"""
import json
from os.path import join, dirname, realpath


def get_config(name):
    path = join(dirname(realpath(__file__)), 'configs', f'{name}.json')
    with open(path, 'r', encoding='utf-8') as f:
        return json.loads(f.read())
