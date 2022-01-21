#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: lxml_demo.py
@time: 2022/1/4 19:33
@project: python3-web-spider-learning
@desc: 3.1 lxml库的使用（P91~P98）
"""
from lxml import etree


def lxml_demo():
    text = '''
    <div>
      <ul>
        <li class="item-0"><a href="link1.html">first item</a></li>
        <li class="item-1"><a href="link2.html">second item</a></li>
        <li class="item-inactive"><a href="link3.html">third item</a></li>
        <li class="item-1"><a href="link4.html">fourth item</a></li>
        <li class="item-0"><a href="link5.html">fifth item</a>
      </ul>
    </div>
    '''
    html = etree.HTML(text)
    result = etree.tostring(html)
    print(result.decode('utf-8'))


def print_html():
    """读取文件，并打印html
    """
    html = etree.parse('files/test.html', etree.HTMLParser())
    result = etree.tostring(html)
    print(result.decode('utf-8'))


def get_nodes():
    """选取指定节点
    """
    html = etree.parse('files/test.html', etree.HTMLParser())
    result = html.xpath('//li')
    print(result)
    print(result[0])


def get_subnodes():
    """选取子节点
    """
    html = etree.parse('files/test.html', etree.HTMLParser())
    result = html.xpath('//li/a')
    print(result)


def get_parent_node():
    """选取父节点
    """
    html = etree.parse('files/test.html', etree.HTMLParser())
    result = html.xpath('//a[@href="link4.html"]/../@class')
    print(result)


def attr_match():
    """匹配指定的属性
    """
    html = etree.parse('files/test.html', etree.HTMLParser())
    result = html.xpath('//li[@class="item-0"]')
    print(result)


def get_text():
    """获取文本
    """
    html = etree.parse('files/test.html', etree.HTMLParser())
    result = html.xpath('//li[@class="item-0"]/a/text()')
    print(result)


def get_attrs():
    """获取属性
    """
    html = etree.parse('files/test.html', etree.HTMLParser())
    result = html.xpath('//li/a/@href')
    print(result)


def attr_values_match():
    """匹配多值属性
    """
    text = '''
    <li class="li li-first"><a href="link.html">first item</a></li>
    '''
    html = etree.HTML(text)
    result = html.xpath('//li[contains(@class, "li")]/a/text()')
    print(result)


def attrs_match():
    """多属性匹配
    """
    text = '''
    <li class="li li-first" name="item"><a href="link.html">first item</a></li>
    '''
    html = etree.HTML(text)
    result = html.xpath('//li[contains(@class, "li") and @name="item"]/a/text()')
    print(result)


def get_nodes_by_order():
    """按序选择
    """
    text = '''
    <div>
      <ul>
        <li class="item-0"><a href="link1.html">first item</a></li>
        <li class="item-1"><a href="link2.html">second item</a></li>
        <li class="item-inactive"><a href="link3.html">third item</a></li>
        <li class="item-1"><a href="link4.html">fourth item</a></li>
        <li class="item-0"><a href="link5.html">fifth item</a>
      </ul>
    </div>
    '''
    html = etree.HTML(text)
    result = html.xpath('//li[1]/a/text()')
    print(result)
    result = html.xpath('//li[last()]/a/text()')
    print(result)
    result = html.xpath('//li[position()<3]/a/text()')
    print(result)
    result = html.xpath('//li[last()-2]/a/text()')
    print(result)


def get_nodes_by_axis():
    """节点轴选择
    """
    text = '''
    <div>
      <ul>
        <li class="item-0"><a href="link1.html"><span>first item</span></a></li>
        <li class="item-1"><a href="link2.html">second item</a></li>
        <li class="item-inactive"><a href="link3.html">third item</a></li>
        <li class="item-1"><a href="link4.html">fourth item</a></li>
        <li class="item-0"><a href="link5.html">fifth item</a>
      </ul>
    </div>
    '''
    html = etree.HTML(text)
    result = html.xpath('//li[1]/ancestor::*')
    print(result)
    result = html.xpath('//li[1]/ancestor::div')
    print(result)
    result = html.xpath('//li[1]/attribute::*')
    print(result)
    result = html.xpath('//li[1]/child::a[@href="link1.html"]')
    print(result)
    result = html.xpath('//li[1]/descendant::span')
    print(result)
    result = html.xpath('//li[1]/following::*[2]')
    print(result)
    result = html.xpath('//li[1]/following-sibling::*')
    print(result)


if __name__ == '__main__':
    get_nodes_by_axis()
