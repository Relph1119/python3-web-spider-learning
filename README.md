# 《Python3网络爬虫开发实战》学习笔记

&emsp;&emsp;崔大（崔庆才）的《Python3网络爬虫开发实战》（第2版）主要通过Python3编程语言，讲解网络爬虫开发中遇到的问题，并通过一个个实战案例，介绍相关的爬虫工具，可分为4个部分：
1. 爬虫相关知识（第1章~第6章）：主要内容包括爬虫的基础知识、基本爬虫操作、网页解析库的基本用法（XPath、Beautiful Soup、pyquery和parsel）、数据的存储（结合MySQL、MongoDB、Redis、Elasticsearch和RabbitMQ）、Ajax数据爬取过程、异步爬虫知识
2. 网页爬虫实战（第7章~第11章）：主要包括动态渲染页面爬取、处理验证码、使用代理、模拟登录、JavaScript逆向（重头章）
3. App爬取与逆向（第12章和第13章）：主要包括App的爬取（抓包软件使用、模拟手机操作的数据爬取）、Android逆向
4. 爬虫高阶实战（第14章~第17章）：主要包括页面智能解析、Scrapy爬虫框架、分布式爬虫、分布式爬虫部署及管理

官方项目代码库：https://github.com/Python3WebSpider

## 目录结构

<pre>
src---------------------------------------------------------实验代码
|   +---ch01------------------------------------------------第1章代码
|   |   +---test.html---------------------------------------网页的结构（P14）
|   +---ch02------------------------------------------------第2章代码
|   |   +---urllib_demo-------------------------------------2.1 urllib的使用
|   |   |   +---request_demo.py-----------------------------Request模块示例（P30~P34）
|   |   |   +---request_hander_demo.py----------------------验证、代理、Cookie（P35-P36）
|   |   |   +---parse_demo.py-------------------------------parse模块示例（P40~P44）
|   |   |   +---robotparser_demo.py-------------------------Robots协议（P46）
|   |   +---requests_demo-----------------------------------2.2 requests的使用
|   |   |   +---requests_demo.py----------------------------requests基本用法（P48~P55）
|   |   |   +---advanced_use.py-----------------------------requests高级用法（P55~P63）
|   |   +---regx_demo.py------------------------------------2.3 正则表达式（P66~P73）
|   |   +---httpx_demo.py-----------------------------------2.4 httpx的使用（P75~P78）
|   |   +---basic_scrape_demo.py----------------------------2.5 基础爬虫案例实战（P78~P89）
|   +---ch03------------------------------------------------第3章代码
|   |   +---lxml_demo.py------------------------------------3.1 lxml库的使用（P91~P98）
|   |   +---beautifulsoup_demo.py---------------------------3.2 Beautiful Soup的使用（P100~P112）
|   |   +---pyquery_demo.py---------------------------------3.3 pyquery的使用（P113~P124）
|   |   +---parsel_demo.py----------------------------------3.4 parsel的使用（P124~P127）
|   +---ch04------------------------------------------------第4章代码
|   |   +---text_oper_demo.py-------------------------------4.1 TXT文本存储（P128~P130）
|   |   +---csv_oper_demo.py--------------------------------4.3 CSV文件存储（P134~P138）
|   |   +---mysql_oper_demo.py------------------------------4.4 MySQL存储（P138~P144）
|   |   +---mongodb_demo.py---------------------------------4.5 MongoDB文档存储（P144~P150）
|   |   +---elasticsearch_oper_demo.py----------------------4.7 Elasticsearch搜索引擎存储（P161~P166）
|   |   +---mongodb_demo.py---------------------------------4.8 RabbitMQ的使用
|   |   |   +---consumer.py---------------------------------RabbitMQ 消费者示例（P167）
|   |   |   +---producer.py---------------------------------RabbitMQ 生产者示例（P169）
|   |   |   +---scrape_producer.py--------------------------RabbitMQ实战 生产者（P171）
|   |   |   +---scrape_consume.py---------------------------RabbitMQ实战 消费者（P172）
|   +---ch05------------------------------------------------第5章代码
|   |   +---scrape_ajax.py----------------------------------5.3 Ajax分析与爬取实战（P184~P190）
|   +---ch06------------------------------------------------第6章代码
|   |   +---coroutine_demo----------------------------------6.1 协程的基本原理
|   |   |   +---coroutine_simple_demo.py--------------------定义协程（P194）
|   |   |   +---coroutine_task1.py--------------------------协程task的使用（P194）
|   |   |   +---coroutine_task2.py--------------------------协程task的使用（P195）
|   |   |   +---multi_task_coroutine.py---------------------多任务协程（P196）
|   |   |   +---bing_callback.py----------------------------绑定回调（P196）
|   |   |   +---coroutine_await_aiohttp.py------------------协程实现，await、aiohttp的使用（P197）
|   |   +---aiohttp_demo------------------------------------6.2 aiohttp的使用
|   |   |   +---simple_demo.py------------------------------aiohttp基本实例（P202）
|   |   |   +---url_params.py-------------------------------URL参数设置（P203）
|   |   |   +---post_request.py-----------------------------POST请求（P203）
|   |   |   +---response_demo.py----------------------------响应（P205）
|   |   |   +---timeout_demo.py-----------------------------超时设置（P205）
|   |   |   +---concurrency_demo.py-------------------------并发限制（P206）
|   |   +---aiohttp_scrape_demo.py--------------------------6.3 aiohttp异步爬取实战（P207~P211）
|   +---ch07------------------------------------------------第7章代码
|   |   +---selenium_demo-----------------------------------7.1 Selunium的使用
|   |   |   +---simple_demo.py------------------------------Selenium基本用法（P213）
|   |   |   +---node_selector.py----------------------------查找节点（P215-P216）
|   |   |   +---node_interaction.py-------------------------节点交互（P216）
|   |   |   +---action_chain.py-----------------------------动作链（P217）
|   |   |   +---node_info.py--------------------------------获取节点信息（P218）
|   |   |   +---switch_frame.py-----------------------------切换Frame（P219）
|   |   |   +---delay_wait.py-------------------------------延时等待（P220）
|   |   |   +---back_forward.py-----------------------------前进和后退（P221）
|   |   |   +---cookie_oper.py------------------------------Cookie操作（P222）
|   |   |   +---tab_oper.py---------------------------------选项卡管理（P222）
|   |   |   +---exception_handle.py-------------------------异常处理（P223）
|   |   |   +---anti_shield.py------------------------------反屏蔽（P224）
|   |   |   +---headless_mode.py----------------------------无头模式（P225）
|   |   +---pyppeteer_demo----------------------------------7.3 Pyppeteer的使用
|   |   |   +---simple_demo.py------------------------------pyppeteer基本使用（P243）
|   |   |   +---dev_mode.py---------------------------------调试模式（P247）
|   |   |   +---prevent_detect.py---------------------------防止检测（P248-P250）
|   |   |   +---incognito_mode.py---------------------------无痕模式（P252）
|   |   |   +---page_demo.py--------------------------------Page对象示例（P253~P256）
|   |   +---playwright_demo---------------------------------7.4 Playwright的使用
|   |   |   +---simple_demo.py------------------------------Playwright基本使用（P257）
|   |   |   +---mobile_web.py-------------------------------支持移动端浏览器（P261）
|   |   |   +---event_listen.py-----------------------------事件监听（P263）
|   |   +---selenium_scrape.py------------------------------7.5 Selenium爬取实战（P269）
|   |   +---pyppeteer_scrape.py-----------------------------7.6 Pyppeteer爬取实战（P276）
|   |   +---css_locate_scrape.py----------------------------7.7 CSS位置偏移反爬与爬取实战（P282）
|   |   +---font_scrape.py----------------------------------7.8 字体反爬与爬取案例（P287）
|   +---ch08------------------------------------------------第8章代码
|   |   +---tesserocr_demo.py-------------------------------8.1 使用OCR技术识别图形验证码（P296）
|   |   +---opencv_demo.py----------------------------------8.2 使用OpenCV识别滑动验证码的缺口（P298~P303）
|   +---ch09------------------------------------------------第9章代码
|   |   +---proxy_demo.py-----------------------------------9.1 代理的设置（P332-P340）
|   +---ch10------------------------------------------------第10章代码
|   |   +---session_cookie_simulate_login.py----------------10.2 基于Session和Cookie的模拟登录爬取实战（P376）
|   |   +---jwt_simulate_login.py---------------------------10.3 基于JWT的模拟登录爬取实战（P381）
|   |   +---account_pool------------------------------------10.4 大规模账号池的搭建（P385~P396）
|   |   +---antispider_scrape_with_account_pool.py----------使用账号池爬取网页（P394）
|   +---ch11------------------------------------------------第11章代码
|   |   +---execjs_demo.py----------------------------------11.5 使用Python模拟执行javascript（P446）
|   |   +---nodejs_demo-------------------------------------11.6 使用Node.js模拟执行JavaScript
|   |   |   +---nodejs_main.js------------------------------使用Node.js模拟执行JavaScript（P451）
|   |   |   +---nodejs_server.js----------------------------搭建nodejs服务（P453）
|   |   |   +---nodejs_client.py----------------------------Python调用Node.js服务（P453）
|   |   +---execjs_web_demo.py------------------------------11.7 浏览器环境下JavaScript的模拟执行（P457）
|   |   +---learn-ast---------------------------------------11.8 AST技术简介
|   |   +---pywasm_scrape_demo.py---------------------------11.11 WebAssembly案例分析和爬取实战（P495）
|   |   +---wasmer_scrape_demo.py---------------------------wasmer库实战（P497）
|   |   +---js_scrape_practice.py---------------------------11.13 JavaScript逆向爬虫实战（P507）
|   +---ch12------------------------------------------------第12章代码
|   |   +---appium_demo.py----------------------------------12.4 Appium的使用（P557）
|   |   +---appium_scrape_practice.py-----------------------12.5 基于Appium的App爬取实战（P562）
|   |   +---airtest_script.py-------------------------------12.7 基于Airtest的App爬取实战（P586）
|   +---ch13------------------------------------------------第13章代码
|   |   +---jeb_demo.py-------------------------------------13.2 JEB的使用（P624）
|   |   +---frida_appbasic1_demo.py-------------------------13.5 Frida的使用，AppBasic1（P645）
|   |   +---frida_appbasic2_demo.py-------------------------13.5 Frida的使用，AppBasic2（P648）
|   |   +---ida_demo.py-------------------------------------13.8 IDA Pro静态分析和动态调试so文件（汇编代码调试）（P679）
|   |   +---frida_rpc_demo.py-------------------------------13.9 基于Frida-RPC 模拟执行so文件（P683）
|   |   +---AndServerTest-----------------------------------13.10 基于AndServer-RPC模拟执行so文件（APP）（P685~690）
|   |   +---andserver_demo.py-------------------------------13.10 基于AndServer-RPC模拟执行so文件（Python爬取数据）（P691）
|   +---ch14------------------------------------------------第14章代码
|   |   +---detail_ai_extract.py----------------------------14.3 详情页智能解析算法的实现（P714）
|   |   +---ai_extract.md-----------------------------------智能解析实现思路
|   +---ch15------------------------------------------------第15章代码
|   |   +---scrapytutorial----------------------------------15.2 Scrapy入门（P743）
|   |   +---scrapyspiderdemo--------------------------------15.4 Spider的使用（P759）
|   |   +---scrapydownloadermiddlewaredemo------------------15.5 Downloader Middleware的使用（P770）
|   |   +---scrapyspidermiddlewaredemo----------------------15.6 Spider Middleware的使用（P775）
|   |   +---scrapyitempipelinedemo--------------------------15.7 Item Pipeline的使用（P781）
|   |   +---scrapyseleniumdemo------------------------------15.9 Scrapy对接Selenium（P797）
|   |   +---scrapypyppeteerdemo-----------------------------15.11 Scrapy对接Pyppeteer（P807）
|   |   +---scrape_processor_demo.py------------------------15.12 Scrapy规则化爬虫（P816）
|   |   +---scrapyuniversaldemo-----------------------------15.12 Scrapy规则化爬虫（实战，P818）
|   |   +---scrape_selector_demo.py-------------------------15.3 Selector的使用（P754）
requirements.txt--------------------------------------------运行环境依赖包
</pre>

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

## 建议学习时间安排

总共学习时间：18天
- Task01：爬虫基础（1天）
- Task02：基本库的使用（2天）
- Task03：网页数据的解析提取（1天）
- Task04：数据的存储（1天）
- Task05：Ajax数据爬取（0.5天）
- Task06：异步爬虫（0.5天）
- Task07：JavaScript动态渲染页面爬取（2天）
- Task08：验证码的识别（0.5天）
- Task09：代理的使用（0.5天）
- Task10：模拟登录（1天）
- Task11：JavaScript逆向爬虫（2天）
- Task12：App数据的爬取（1天）
- Task13：Android逆向（1天）
- Task14：页面智能解析（1天）
- Task15：Scrapy框架的使用（1.5天）
- Task16：分布式爬虫（0.5天）
- Task17：爬虫的管理和部署（1天）