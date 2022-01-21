#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: csv_oper_demo.py
@time: 2022/1/5 19:20
@project: python3-web-spider-learning
@desc: 4.3 CSV文件存储（P134~P138）
"""
import csv


def write_to_csv():
    with open('files/data.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['id', 'name', 'age'])
        writer.writerow(['10001', 'Mike', 20])
        writer.writerow(['10002', 'Bob', 22])
        writer.writerow(['10003', 'Jordan', 21])


def write_dict_to_csv():
    with open('files/data.csv', 'w', encoding='utf-8', newline='') as csv_file:
        filednames = ['id', 'name', 'age']
        writer = csv.DictWriter(csv_file, fieldnames=filednames)
        writer.writeheader()
        writer.writerow({'id': '10001', 'name': 'Mike', 'age': 20})
        writer.writerow({'id': '10002', 'name': 'Bob', 'age': 22})
        writer.writerow({'id': '10003', 'name': 'Jordan', 'age': 21})


def read_csv():
    with open('files/data.csv', 'r', encoding='utf-8') as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            print(row)


if __name__ == '__main__':
    write_dict_to_csv()
    read_csv()
