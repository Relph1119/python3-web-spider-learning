#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: jwt_simulate_login.py
@time: 2022/1/12 9:49
@project: python3-web-spider-learning
@desc: 10.3 基于JWT的模拟登录爬取实战（P381）
"""
from urllib.parse import urljoin
import requests

BASE_URL = 'https://login3.scrape.center/'
LOGIN_URL = urljoin(BASE_URL, '/api/login')
INDEX_URL = urljoin(BASE_URL, '/api/book')
USERNAME = 'admin'
PASSWORD = 'admin'

response_login = requests.post(LOGIN_URL, json={
    'username': USERNAME,
    'password': PASSWORD
})
data = response_login.json()
print('Response JSON:', data)
# 获取token jwt
jwt = data.get('token')
print('JWT:', jwt)

headers = {
    'Authorization': f'jwt {jwt}'
}
response_index = requests.get(INDEX_URL, params={
    'limit': 18,
    'offset': 0
}, headers=headers)
print('Response Status', response_index.status_code)
print('Response URL', response_index.url)
print('Response Data', response_index.json())
