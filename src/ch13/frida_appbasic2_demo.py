#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: frida_appbasic2_demo.py
@time: 2022/1/17 17:43
@project: python3-web-spider-learning
@desc: 13.5 Frida的使用，AppBasic2（P648）
"""
import sys

import frida

CODE = open('files/frida_appbasic2.js', encoding='utf-8').read()
PROCESS_NAME = 'AppBasic2'


def on_message(message, data):
    print(message)


process = frida.get_usb_device().attach(PROCESS_NAME)
script = process.create_script(CODE)
script.on('message', on_message)
script.load()
sys.stdin.read()
