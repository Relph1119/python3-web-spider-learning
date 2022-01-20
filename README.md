# 《Python3网络爬虫开发实战》学习笔记

&emsp;&emsp;崔大（崔庆才）的《Python3网络爬虫开发实战》（第2版）主要通过Python3编程语言，讲解网络爬虫开发中遇到的问题，并通过一个个实战案例，介绍相关的爬虫工具，可分为4个部分：
1. 爬虫相关知识（第1章~第6章）：主要内容包括爬虫的基础知识、基本爬虫操作、网页解析库的基本用法（XPath、Beautiful Soup、pyquery和parsel）、数据的存储（结合MySQL、MongoDB、Redis、Elasticsearch和RabbitMQ）、Ajax数据爬取过程、异步爬虫知识

2. 网页爬虫实战（第7章~第11章）：主要包括动态渲染页面爬取、处理验证码、使用代理、模拟登录、JavaScript逆向（重头章）

3. App爬取与逆向（第12章和第13章）：主要包括App的爬取（抓包软件使用、模拟手机操作的数据爬取）、Android逆向

4. 爬虫高阶实战（第14章~第17章）：主要包括页面智能解析、Scrapy爬虫框架、分布式爬虫、分布式爬虫部署及管理

官方项目代码库：https://github.com/Python3WebSpider

## 目录结构

## 运行环境

### 安装python虚拟环境
Mini-Conda Python 3.8 Windows环境
```shell
conda create --prefix venv python=3.8
```

### 安装相关的依赖包
```shell
pip install -r requirements.txt
```

### 安装Tesseract（用于离线文字识别）  
```shell
conda install -c conda-forge tesserocr
```
参考网址：https://setup.scrape.center/tesserocr

### 用VBox安装安卓虚拟机（Android-x86 6.0版本）
- 参考网址：https://www.cnblogs.com/wynn0123/p/6288344.html
- 连接虚拟机的命令：`adb connect <ip>`
- 例如将`scrape-app5.apk`文件上传到安卓虚拟机的命令：`adb push scrape-app5.apk /sdcard`

### pip批量导出环境中所有组件
```shell
pip freeze > requirements.txt
```

## 问题汇总

### 问题1 证书过期问题`certificate has expired`
```log
raise ClientConnectorCertificateError(req.connection_key, exc) from exc
aiohttp.client_exceptions.ClientConnectorCertificateError: Cannot connect to host antispider6.scrape.center:443 ssl:True [SSLCertVerificationError: (1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1131)')]
```
**解决方案：**
```python
import aiohttp
from aiohttp import TCPConnector
session = aiohttp.ClientSession(connector=TCPConnector(ssl=False))
```

### 问题2 运行配置twisted的异步报错问题
```log
TypeError: ProactorEventLoop is not supported, got: <ProactorEventLoop running=False closed=False debug=False>
```
**解决方案：**  
在Windows环境的Python3.8下，需要在spider中添加如下代码：
```python
import asyncio

asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
```