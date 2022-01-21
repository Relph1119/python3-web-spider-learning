#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: pyquery_demo.py
@time: 2022/1/5 8:49
@project: python3-web-spider-learning
@desc: 3.3 pyquery的使用（P113~P124）
"""

from pyquery import PyQuery as pq

html = '''
    <div id="container">
        <ul class="list">
             <li class="item-0">first item</li>
             <li class="item-1"><a href="link2.html">second item</a></li>
             <li class="item-0 active"><a href="link3.html"><span class="bold">third item</span></a></li>
             <li class="item-1 active"><a href="link4.html">fourth item</a></li>
             <li class="item-0"><a href="link5.html">fifth item</a></li>
         </ul>
     </div>
    '''

html_wrap = '''
    <div class="wrap">
        <div id="container">
            <ul class="list">
                 <li class="item-0">first item</li>
                 <li class="item-1"><a href="link2.html">second item</a></li>
                 <li class="item-0 active"><a href="link3.html"><span class="bold">third item</span></a></li>
                 <li class="item-1 active"><a href="link4.html">fourth item</a></li>
                 <li class="item-0"><a href="link5.html">fifth item</a></li>
             </ul>
         </div>
    </div>
    '''


def init_pyquery_demo():
    doc = pq(html)
    print(doc('li'))

    doc = pq(url='https://cuiqingcai.com', encoding='utf-8')
    doc('title')


def css_selector_demo():
    doc = pq(html)
    print(doc('#container .list li'))
    print(type(doc('#container .list li')))

    for item in doc('#container .list li').items():
        print(item.text())


def get_child_nodes():
    doc = pq(html)
    items = doc('.list')
    print(type(items))
    print(items)
    lis = items.find('li')
    print(type(lis))
    print(lis)

    lis = items.children()
    print(type(lis))
    print(lis)


def get_parent_node():
    doc = pq(html_wrap)
    items = doc('.list')
    container = items.parent()
    print(type(container))
    print(container)


def get_ancestor_node():
    doc = pq(html_wrap)
    items = doc('.list')
    parents = items.parents()
    print(type(parents))
    print(parents)

    parent = items.parents('.wrap')
    print(parent)


def get_borther_nodes():
    doc = pq(html)
    li = doc('.list .item-0.active')
    print(li.siblings('.active'))


def get_node():
    doc = pq(html)
    li = doc('.item-0.active')
    print(li)
    print(str(li))


def get_nodes():
    doc = pq(html)
    lis = doc('li').items()
    print(type(lis))
    for li in lis:
        print(li, type(li))


def get_attr():
    doc = pq(html_wrap)
    a = doc('.item-0.active a')
    print(a, type(a))
    print(a.attr('href'))


def get_attrs():
    doc = pq(html_wrap)
    a = doc('a')
    for item in a.items():
        print(item.attr('href'))


def get_node_text():
    doc = pq(html_wrap)
    a = doc('.item-0.active a')
    li = doc('.item-0.active')
    print(a)
    print(a.text())
    print(li)
    print(li.html())


def add_remove_class():
    doc = pq(html_wrap)
    li = doc('.item-0.active')
    print(li)
    li.remove_class('active')
    print(li)
    li.add_class('active')
    print(li)


def attr_text_html():
    html = '''
    <ul class="list">
         <li class="item-0 active"><a href="link3.html"><span class="bold">third item</span></a></li>
    </ul>
    '''
    doc = pq(html)
    li = doc('.item-0.active')
    print(li)
    li.attr('name', 'link')
    print(li)
    li.text('changed item')
    print(li)
    li.html('<span>changed item</span>')
    print(li)


def remove_element():
    html = '''
    <div class="wrap">
        Hello, World
        <p>This is a paragraph.</p>
     </div>
    '''
    doc = pq(html)
    wrap = doc('.wrap')
    print(wrap.text())

    wrap.find('p').remove()
    print(wrap.text())


def fake_css_selector():
    # 伪CSS选择器
    html = '''
    <div class="wrap">
        <div id="container">
            <ul class="list">
                 <li class="item-0">first item</li>
                 <li class="item-1"><a href="link2.html">second item</a></li>
                 <li class="item-0 active"><a href="link3.html"><span class="bold">third item</span></a></li>
                 <li class="item-1 active"><a href="link4.html">fourth item</a></li>
                 <li class="item-0"><a href="link5.html">fifth item</a></li>
             </ul>
         </div>
     </div>
    '''
    doc = pq(html)
    li = doc('li:first-child')
    print(li)
    li = doc('li:last-child')
    print(li)
    li = doc('li:nth-child(2)')
    print(li)
    li = doc('li:gt(2)')
    print(li)
    li = doc('li:nth-child(2n)')
    print(li)
    li = doc('li:contains(second)')
    print(li)


if __name__ == '__main__':
    fake_css_selector()
