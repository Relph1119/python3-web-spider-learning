#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: frida_demo.py
@time: 2022/1/17 17:20
@project: python3-web-spider-learning
@desc: 13.5 Frida的使用，AppBasic1（P645）
"""
import sys

import frida

CODE = open('files/frida_appbasic1.js', encoding='utf-8').read()
PROCESS_NAME = 'AppBasic1'


def on_message(message, data):
    print(message)


process = frida.get_usb_device().attach(PROCESS_NAME)
script = process.create_script(CODE)
script.on('message', on_message)
script.load()
sys.stdin.read()
