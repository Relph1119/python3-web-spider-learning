#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: js_scrape_practice.py
@time: 2022/1/14 18:50
@project: python3-web-spider-learning
@desc: 11.13 JavaScript逆向爬虫实战（P507）
目标：爬取网页（https://spa6.scrape.center/）
重难点：
（1）列表页的Ajax接口参数带有加密的token
（2）详情页的URL带有加密id
（3）详情页的Ajax接口参数带有加密id和加密token
（4）Ajax接口存在时效性，过段时间会返回401
（5）前端JavaScript有压缩和混淆
逆向爬取思路：
（1）通过全局搜索token，得到构造Ajax请求，设置断点
（2）分析列表页加密逻辑，查看各变量的值，得到基本思路：将/api/movie放入一个列表中，加入当前时间戳，用逗号拼接，进行SHA1编码，将编码结果再次进行拼接
将拼接后的结果进行Base64编码
（3）分析详情页加密id逻辑：使用Hook btoa，推荐使用Tampermonkey注入，分析得到：将一个固定值加上id进行Base64编码
（4）分析详情页Ajax的token：得到与列表页token的构造逻辑是一样的
"""
import base64
import hashlib
import time

import requests

INDEX_URL = 'https://spa6.scrape.center/api/movie?limit={limit}&offset={offset}&token={token}'
DETAIL_URL = 'https://spa6.scrape.center/api/movie/{id}?token={token}'
LIMIT = 10
OFFSET = 0
SECRET = 'ef34#teuq0btua#(-57w1q5o5--j@98xygimlyfxs*-!i-0-mb'


# 得到token
def get_token(args: list):
    timestamp = str(int(time.time()))
    args.append(timestamp)
    sign = hashlib.sha1(','.join(args).encode('utf-8')).hexdigest()
    return base64.b64encode(','.join([sign, timestamp]).encode('utf-8')).decode('utf-8')


args = ['/api/movie']
token = get_token(args)
# 得到列表页的URL
index_url = INDEX_URL.format(limit=LIMIT, offset=OFFSET, token=token)
response = requests.get(index_url)
print('response:', response.json())

result = response.json()

for item in result['results']:
    id = item['id']
    encrypt_id = base64.b64encode((SECRET + str(id)).encode('utf-8')).decode('utf-8')
    args = [f'/api/movie/{encrypt_id}']
    token = get_token(args=args)
    # 得到详情页的URL
    detail_url = DETAIL_URL.format(id=encrypt_id, token=token)
    response = requests.get(detail_url)
    print('detail response:', response.json())
