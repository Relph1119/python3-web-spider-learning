#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: regx_demo.py
@time: 2022/1/4 9:33
@project: python3-web-spider-learning
@desc: 2.3 正则表达式（P66~P73）
"""
import re

html = '''<div id="songs-list">
    <h2 class="title">经典老歌</h2>
    <p class="introduction">
        经典老歌列表
    </p>
    <ul id="list" class="list-group">
        <li data-view="2">一路有你</li>
        <li data-view="7">
            <a href="/2.mp3" singer="任贤齐">沧海一声笑</a>
        </li>
        <li data-view="4" class="active">
            <a href="/3.mp3" singer="齐秦">往事随风</a>
        </li>
        <li data-view="6"><a href="/4.mp3" singer="beyond">光辉岁月</a></li>
        <li data-view="5"><a href="/5.mp3" singer="陈慧琳">记事本</a></li>
        <li data-view="5">
            <a href="/6.mp3" singer="邓丽君">但愿人长久</a>
        </li>
    </ul>
</div>'''


def regex_match():
    content = 'Hello 123 4567 World_This is a Regex Demo'
    print(len(content))
    result = re.match('^Hello\s\d\d\d\s\d{4}\s\w{10}', content)
    print(result)
    print(result.group())
    print(result.span())


def match_object():
    # 匹配目标
    content = 'Hello 1234567 World_This is a Regex Demo'
    result = re.match('^Hello\s(\d+)\sWorld', content)
    print(result)
    print(result.group())
    print(result.group(1))
    print(result.span())


def common_match():
    # 通用匹配
    content = 'Hello 123 4567 World_This is a Regex Demo'
    result = re.match('^Hello.*Demo$', content)
    print(result)
    print(result.group())
    print(result.span())


def greedy_match():
    # 贪婪匹配
    content = 'Hello 123 4567 World_This is a Regex Demo'
    result = re.match('^He.*?(\d+).*Demo$', content)
    print(result)
    print(result.group())
    print(result.span())


def match_with_modifier():
    # 使用修饰符
    content = '''Hello 1234567 World_This
    is a Regex Demo'''
    result = re.match('^He.*?(\d+).*?Demo$', content, re.S)
    print(result.group(1))


def transferred_match():
    # 转义匹配
    content = '(百度)www.baidu.com'
    result = re.match('\(百度\)www\.baidu\.com', content)
    print(result)


def search_match():
    regx = '<li.*?active.*?singer="(.*?)">(.*?)</a>'
    result = re.search(regx, html, re.S)
    if result:
        print(result.group(1), result.group(2))


def findall_match():
    regx = '<li.*?href="(.*?)".*?singer="(.*?)">(.*?)</a>'
    results = re.findall(regx, html, re.S)
    print(results)
    print(type(results))
    for result in results:
        print(result)
        print(result[0], result[1], result[2])


def sub_match():
    # 替换
    content = '54aK54yr5oiR54ix5L2g'
    content = re.sub('\d+', '', content)
    print(content)


def sub_html_match():
    content = re.sub('<a.*?>|</a>', '', html)
    print(content)
    results = re.findall('<li.*?>(.*?)</li>', content, re.S)
    for result in results:
        print(result.strip())


if __name__ == '__main__':
    sub_html_match()
