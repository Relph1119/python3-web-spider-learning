#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: tesserocr_demo.py
@time: 2022/1/11 9:37
@project: python3-web-spider-learning
@desc: 8.1 使用OCR技术识别图形验证码（P296）
"""
import re
import time
from io import BytesIO

import numpy as np
import tesserocr
from PIL import Image
from retrying import retry
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def preprocess(image):
    image = image.convert('L')
    array = np.array(image)
    array = np.where(array > 115, 255, 0)
    image = Image.fromarray(array.astype('uint8'))
    return image


@retry(stop_max_attempt_number=10, retry_on_result=lambda x: x is False)
def login():
    """
    最大尝试10次
    """
    browser.get('https://captcha7.scrape.center/')
    browser.find_element_by_css_selector('.username input[type="text"]').send_keys('admin')
    browser.find_element_by_css_selector('.password input[type="password"]').send_keys('admin')
    captcha = browser.find_element_by_css_selector('#captcha')
    image = Image.open(BytesIO(captcha.screenshot_as_png))
    image = preprocess(image)
    captcha = tesserocr.image_to_text(image)
    captcha = re.sub('[^A-Za-z0-9]', '', captcha)
    print("Captcha:", captcha)
    browser.find_element_by_css_selector('.captcha input[type="text"]').send_keys(captcha)
    browser.find_element_by_css_selector('.login').click()

    try:
        WebDriverWait(browser, 4).until(EC.presence_of_element_located((By.XPATH, '//h2[contains(., "登录成功")]')))
        time.sleep(10)
        browser.close()
        return True
    except TimeoutException:
        return False


if __name__ == '__main__':
    browser = webdriver.Chrome()
    login()
