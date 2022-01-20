#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: loaders.py
@time: 2022/1/20 16:36
@project: python3-web-spider-learning
@desc: 
"""

from scrapy.loader import ItemLoader
from itemloaders.processors import TakeFirst, Identity, Compose


class MovieItemLoader(ItemLoader):
    default_output_processor = TakeFirst()
    categories_out = Identity()
    score_out = Compose(TakeFirst(), str.strip)
    drama_out = Compose(TakeFirst(), str.strip)