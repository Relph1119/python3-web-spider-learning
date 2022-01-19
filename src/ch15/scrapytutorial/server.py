#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: server.py
@time: 2022/1/19 18:38
@project: python3-web-spider-learning
@desc: 15.8 Extension的使用（P793）
"""
from flask import Flask, request, jsonify
from loguru import logger

app = Flask(__name__)


@app.route('/notify', methods=['POST'])
def receive():
    post_data = request.get_json()
    event = post_data.get('event')
    data = post_data.get('data')
    logger.debug(f'received event {event}, data {data}')
    return jsonify(status='success')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
