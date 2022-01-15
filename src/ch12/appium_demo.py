#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: appium_demo.py
@time: 2022/1/16 2:26
@project: python3-web-spider-learning
@desc: 12.4 Appium的使用（P557）
"""
from appium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

server = 'http://localhost:4723/wd/hub'
desired_capabilitis= {
  "platformName": "Android",
  "appium:deviceName": "VirtualBox",
  "appium:appPackage": "com.goldze.mvvmhabit",
  "appium:appActivity": "com.goldze.mvvmhabit.ui.MainActivity",
  "appium:noReset": True
}

# 启动示例App
driver = webdriver.Remote(server, desired_capabilitis)
wait = WebDriverWait(driver, 30)
# 等到所有电影条目都加载之后
wait.until(EC.presence_of_element_located((By.XPATH, '//android.support.v7.widget.RecyclerView/android.widget.LinearLayout')))
window_size = driver.get_window_size()
width, height = window_size.get('width'), window_size.get('height')
# 前两个表示初始位置，后两个表示滑动的结束位置，1000表示滑动时间为1秒
driver.swipe(width * 0.5, height * 0.8, width * 0.5, height * 0.2, 1000)