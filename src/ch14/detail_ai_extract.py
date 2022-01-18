#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: detail_ai_extract.py
@time: 2022/1/18 11:15
@project: python3-web-spider-learning
@desc: 14.3 详情页智能解析算法的实现（P714）
实现思路：
（1）提取标题：提取页面的h节点，将内容与title节点的文本进行比较，取出相似度最高的内容，即详情页的标题
（2）提取时间：通过设置meta规则和时间匹配规则，得到时间
（3）提取正文：通过计算文本密度和符号密度，根据得到的分数，取出分数最高的节点，即为正文内容所在的节点，将各节点进行拼接，得到正文
"""
import json
import re

import numpy as np
from lxml import etree
from lxml.html import fromstring, HtmlElement

# 从meta提取标题的规则
TITLE_METAS = [
    '//meta[starts-with(@property, "og:title")]/@content',
    '//meta[starts-with(@name, "og:title")]/@content',
    '//meta[starts-with(@property, "title")]/@content',
    '//meta[starts-with(@name, "title")]/@content',
    '//meta[starts-with(@property, "page:title")]/@content',
]


def extract_by_title_meta(element: HtmlElement) -> str:
    for xpath in TITLE_METAS:
        title = element.xpath(xpath)
        if title:
            return ''.join(title)


def extract_by_title(element: HtmlElement):
    # 对于title节点，直接提取纯文本内容
    return ''.join(element.xpath('//title//text()')).strip()


def extract_by_h(element: HtmlElement):
    # 对于h节点，则提取h1、h2、h3节点的内容
    hs = element.xpath('//h1//text()|//h2//text()|//h3//text()')
    return hs or []


def similarity(s1, s2):
    # 相似度计算
    if not s1 or not s2:
        return 0
    s1_set = set(list(s1))
    s2_set = set(list(s2))
    intersection = s1_set.intersection(s2_set)
    union = s1_set.union(s2_set)
    return len(intersection) / len(union)


def extract_title(element: HtmlElement):
    # 提取标题
    title_extracted_by_meta = extract_by_title_meta(element)
    title_extracted_by_h = extract_by_h(element)
    title_extracted_by_title = extract_by_title(element)

    if title_extracted_by_meta:
        return title_extracted_by_meta

    # 通过计算相似度排序，取相似度最高的那个标题
    title_extracted_by_h = sorted(title_extracted_by_h,
                                  key=lambda x: similarity(x, title_extracted_by_title),
                                  reverse=True)
    if title_extracted_by_h:
        return title_extracted_by_h[0]

    return title_extracted_by_title


CONTENT_USELESS_TAGS = ['meta', 'style', 'script', 'like', 'video', 'iframe', 'source', 'svg', 'path',
                        'symbol', 'img', 'footer', 'header']
CONTENT_STRIP_TAGS = ['span', 'blickquote']
CONTENT_NOISE_XPATHS = [
    '//div[contains(@class, "comment")]',
    '//div[contains(@class, "advertisement")]',
    '//div[contains(@class, "advert")]',
    '//div[contains(@style, "display:none")]',
]


def preprocess4content(element: HtmlElement):
    # 删除标签和内容
    etree.strip_elements(element, *CONTENT_USELESS_TAGS)
    # 只删除标签对
    etree.strip_elements(element, *CONTENT_STRIP_TAGS)
    # 删除噪声标签
    remove_children(element, CONTENT_NOISE_XPATHS)

    for child in children(element):
        # 把span和strong标签里面的文本合并到父级p标签里
        if child.tag.lower() == 'p':
            etree.strip_tags(child, 'span')
            etree.strip_tags(child, 'strong')

            if not (child.text and child.text.strip()):
                remove_element(child)

        # 如果div标签里没有任何子节点，就把这个标签转换为p标签
        if child.tag.lower() == 'div' and not child.getchildren():
            child.tag = 'p'


def remove_element(element: HtmlElement):
    parent = element.getparent()
    if parent is not None:
        parent.remove(element)


def remove_children(element: HtmlElement, xpaths=None):
    if not xpaths:
        return
    for xpath in xpaths:
        nodes = element.xpath(xpath)
        for node in nodes:
            remove_element(node)

    return element


def children(element: HtmlElement):
    yield element
    for child_element in element:
        if isinstance(child_element, HtmlElement):
            yield from children(child_element)


class Element(HtmlElement):
    id: int = None
    tag_name: str = None
    # 节点的总字符数
    number_of_char: int = None
    # 节点内带超链接的字符数
    number_of_a_char: int = None
    # 节点的子孙节点数
    number_of_descendants: int = None
    # 节点内带链接的子孙节点数
    number_of_a_descendants: int = None
    # 节点内的p节点数
    number_of_p_descendants: int = None
    # 节点包含的标点符号数
    number_of_punctuation: int = None
    # 节点的符号密度
    density_of_punctuation: int = None
    # 节点的文本密度
    density_of_text: float = None
    # 最终评分
    density_score: float = None


def number_of_a_char(elememt: Element):
    if elememt is None:
        return 0
    text = ''.join(elememt.xpath('.//a//text()'))
    text = re.sub(r'\s*', '', text, flags=re.S)
    return len(text)


def number_of_p_descendants(element: Element):
    if element is None:
        return 0
    return len(element.xpath('.//p'))


PUNCTUATION = set('''！，。？、；：“”‘’《》%（）<>{}「」【】*～`,.?:;'"!%()''')


def number_of_punctuation(element: Element):
    if element is None:
        return 0
    text = ''.join(element.xpath('.//text()'))
    text = re.sub(r'\s*', '', text, flags=re.S)
    punctuations = [c for c in text if c in PUNCTUATION]
    return len(punctuations)


def density_of_text(element: Element):
    if element.number_of_descendants - element.number_of_a_descendants == 0:
        return 0
    return (element.number_of_char - element.number_of_a_char) / \
           (element.number_of_descendants - element.number_of_a_descendants)


def density_of_punctuation(element: Element):
    result = (element.number_of_char - element.number_of_a_char) / \
             (element.number_of_punctuation + 1)
    return result or 1


def number_of_char(element: Element):
    """
    get number of char, for example, result of `<a href="#">hello</a>world` = 10
    :param element:
    :return: length
    """
    if element is None:
        return 0
    text = ''.join(element.xpath('.//text()'))
    text = re.sub(r'\s*', '', text, flags=re.S)
    return len(text)


def number_of_descendants(element: Element):
    """
    get number of descendants
    :param element:
    :return:
    """
    if element is None:
        return 0
    # return len(element.xpath('.//*'))
    return len(list(descendants(element, including=False)))


def number_of_a_descendants(element: Element):
    """
    get number of a tags in this element
    :param element:
    :return:
    """
    if element is None:
        return 0
    return len(element.xpath('.//a'))


def init_element(element: Element):
    element.id = hash(element)
    element.tag_name = element.tag
    element.number_of_char = number_of_char(element)
    element.number_of_a_char = number_of_a_char(element)
    element.number_of_descendants = number_of_descendants(element)
    element.number_of_a_descendants = number_of_a_descendants(element)
    element.number_of_p_descendants = number_of_p_descendants(element)
    element.number_of_punctuation = number_of_punctuation(element)
    element.density_of_punctuation = density_of_punctuation(element)
    element.density_of_text = density_of_text(element)
    return element


def descendants(element: Element, including=False):
    """
    get descendants clement of specific element
    :param element: parent element
    :param including: including current element or not
    :return:
    """
    if element is None:
        return []
    if including:
        yield element
    for descendant in element.iterdescendants():
        if isinstance(descendant, HtmlElement):
            descendant.__class__ = Element
            init_element(descendant)
            yield descendant


def descendants_of_body(element: Element):
    """
    get descendants element of body element
    :param element:
    :return:
    """
    if element is None:
        return []
    body_xpath = '//body'
    elements = element.xpath(body_xpath)
    if elements:
        elements[0].__class__ = Element
        init_element(elements[0])
        return list(descendants(elements[0], True))
    return []


def extract_content(element: Element):
    # 预处理
    preprocess4content(element)

    # 找出当前节点的子孙节点
    descendants = descendants_of_body(element)

    # 找出所有节点的density_of_text值的方差
    density_of_text = [descendant.density_of_text for descendant in descendants]
    density_of_text_std = np.std(density_of_text, ddof=1)

    # 计算所有节点的density_score值
    for descendant in descendants:
        score = np.log(density_of_text_std) * descendant.density_of_text * \
                np.log10(descendant.number_of_p_descendants + 2) * \
                np.log(descendant.density_of_punctuation)
        descendant.density_score = score

    # 根据density_score对节点进行排序
    descendants = sorted(descendants, key=lambda x: x.density_score, reverse=True)
    descendant_first = descendants[0] if descendants else None
    if descendant_first is None:
        return None
    paragraphs = descendant_first.xpath('.//p//text()')
    paragraphs = [paragraph.strip() if paragraph else '' for paragraph in paragraphs]
    paragraphs = list(filter(lambda x: x, paragraphs))
    text = '\n'.join(paragraphs)
    text = text.strip()
    return text


DATETIME_METAS = [
    '//meta[starts-with(@property, "rnews:datePublished")]/@content',
    '//meta[starts-with(@property, "article:published_time")]/@content',
    '//meta[starts-with(@property, "og:published_time")]/@content',
    '//meta[starts-with(@property, "og:release_date")]/@content',
    '//meta[starts-with(@itemprop, "datePublished")]/@content',
    '//meta[starts-with(@itemprop, "dateUpdate")]/@content',
    '//meta[starts-with(@name, "OriginalPublicationDate")]/@content',
    '//meta[starts-with(@name, "article_date_original")]/@content',
    '//meta[starts-with(@name, "og:time")]/@content',
    '//meta[starts-with(@name, "apub:time")]/@content',
    '//meta[starts-with(@name, "publication_date")]/@content',
    '//meta[starts-with(@name, "sailthru.date")]/@content',
    '//meta[starts-with(@name, "PublishDate")]/@content',
    '//meta[starts-with(@name, "publishdate")]/@content',
    '//meta[starts-with(@name, "PubDate")]/@content',
    '//meta[starts-with(@name, "pubtime")]/@content',
    '//meta[starts-with(@name, "_pubtime")]/@content',
    '//meta[starts-with(@name, "weibo: article:create_at")]/@content',
    '//meta[starts-with(@pubdate, "pubdate")]/@content',
]


def extract_by_datetime_meta(element: HtmlElement):
    for xpath in DATETIME_METAS:
        datetime = element.xpath(xpath)
        if datetime:
            return ''.join(datetime)


REGEXES = [
    "(\d{4}[-|/|.]\d{1,2}[-|/|.]\d{1,2}\s*?[0-1]?[0-9]:[0-5]?[0-9]:[0-5]?[0-9])",
    "(\d{4}[-|/|.]\d{1,2}[-|/|.]\d{1,2}\s*?[2][0-3]:[0-5]?[0-9]:[0-5]?[0-9])",
    "(\d{4}[-|/|.]\d{1,2}[-|/|.]\d{1,2}\s*?[0-1]?[0-9]:[0-5]?[0-9])",
    "(\d{4}[-|/|.]\d{1,2}[-|/|.]\d{1,2}\s*?[2][0-3]:[0-5]?[0-9])",
    "(\d{4}[-|/|.]\d{1,2}[-|/|.]\d{1,2}\s*?[1-24]\d时[0-60]\d分)([1-24]\d时)",
    "(\d{2}[-|/|.]\d{1,2}[-|/|.]\d{1,2}\s*?[0-1]?[0-9]:[0-5]?[0-9]:[0-5]?[0-9])",
    "(\d{2}[-|/|.]\d{1,2}[-|/|.]\d{1,2}\s*?[2][0-3]:[0-5]?[0-9]:[0-5]?[0-9])",
    "(\d{2}[-|/|.]\d{1,2}[-|/|.]\d{1,2}\s*?[0-1]?[0-9]:[0-5]?[0-9])",
    "(\d{2}[-|/|.]\d{1,2}[-|/|.]\d{1,2}\s*?[2][0-3]:[0-5]?[0-9])",
    "(\d{2}[-|/|.]\d{1,2}[-|/|.]\d{1,2}\s*?[1-24]\d时[0-60]\d分)([1-24]\d时)",
    "(\d{4}年\d{1,2}月\d{1,2}日\s*?[0-1]?[0-9]:[0-5]?[0-9]:[0-5]?[0-9])",
    "(\d{4}年\d{1,2}月\d{1,2}日\s*?[2][0-3]:[0-5]?[0-9]:[0-5]?[0-9])",
    "(\d{4}年\d{1,2}月\d{1,2}日\s*?[0-1]?[0-9]:[0-5]?[0-9])",
    "(\d{4}年\d{1,2}月\d{1,2}日\s*?[2][0-3]:[0-5]?[0-9])",
    "(\d{4}年\d{1,2}月\d{1,2}日\s*?[1-24]\d时[0-60]\d分)([1-24]\d时)",
    "(\d{2}年\d{1,2}月\d{1,2}日\s*?[0-1]?[0-9]:[0-5]?[0-9]:[0-5]?[0-9])",
    "(\d{2}年\d{1,2}月\d{1,2}日\s*?[2][0-3]:[0-5]?[0-9]:[0-5]?[0-9])",
    "(\d{2}年\d{1,2}月\d{1,2}日\s*?[0-1]?[0-9]:[0-5]?[0-9])",
    "(\d{2}年\d{1,2}月\d{1,2}日\s*?[2][0-3]:[0-5]?[0-9])",
    "(\d{2}年\d{1,2}月\d{1,2}日\s*?[1-24]\d时[0-60]\d分)([1-24]\d时)",
    "(\d{1,2}月\d{1,2}日\s*?[0-1]?[0-9]:[0-5]?[0-9]:[0-5]?[0-9])",
    "(\d{1,2}月\d{1,2}日\s*?[2][0-3]:[0-5]?[0-9]:[0-5]?[0-9])",
    "(\d{1,2}月\d{1,2}日\s*?[0-1]?[0-9]:[0-5]?[0-9])",
    "(\d{1,2}月\d{1,2}日\s*?[2][0-3]:[0-5]?[0-9])",
    "(\d{1,2}月\d{1,2}日\s*?[1-24]\d时[0-60]\d分)([1-24]\d时)",
    "(\d{4}[-|/|.]\d{1,2}[-|/|.]\d{1,2})",
    "(\d{2}[-|/|.]\d{1,2}[-|/|.]\d{1,2})",
    "(\d{4}年\d{1,2}月\d{1,2}日)",
    "(\d{2}年\d{1,2}月\d{1,2}日)",
    "(\d{1,2}月\d{1,2}日)"
]


def extract_by_regex(elememt: HtmlElement) -> str:
    text = ''.join(elememt.xpath('.//text()'))
    for regex in REGEXES:
        result = re.search(regex, text)
        if result:
            return result.group(1)


def extract_datetime(element):
    return extract_by_datetime_meta(element) or extract_by_regex(element)


def extract(html):
    element = fromstring(html=html)
    data = {
        'title': extract_title(element),
        'datetime': extract_datetime(element),
        'content': extract_content(element),
    }
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


if __name__ == '__main__':
    html = open("files/detail.html", encoding='utf-8').read()
    print(extract(html))
