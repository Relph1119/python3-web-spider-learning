# 《Python3网络爬虫开发实战》学习笔记

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

1. 证书过期问题`certificate has expired`
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