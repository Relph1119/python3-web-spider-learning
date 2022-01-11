# 《Python3网络爬虫开发实战》学习笔记

## 目录结构

## 运行环境

### Python版本
Mini-Conda Python 3.8 Windows环境

### 安装相关的依赖包
```shell
conda install --yes --file requirements.txt
```

### 安装Pytorch
```shell
conda install pytorch torchvision torchaudio cudatoolkit=11.3 -c pytorch
```

### 安装Tesseract（用于离线文字识别）  
```shell
conda install -c conda-forge tesserocr
```
参考网址：https://setup.scrape.center/tesserocr

### 安装opencv
```shell
conda install -c menpo opencv
```

### Conda批量导出环境中所有组件
```shell
conda list -e > requirements.txt
```

