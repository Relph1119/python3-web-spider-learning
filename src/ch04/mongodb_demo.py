#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: mongodb_demo.py
@time: 2022/1/5 20:16
@project: python3-web-spider-learning
@desc: 4.5 MongoDB文档存储（P144~P150）
"""
import pymongo


def insert_data():
    # 插入数据
    student = {
        'id': '20170101',
        'name': 'Jordan',
        'age': 20,
        'gender': 'male'
    }
    result = collection.insert_one(student)
    print(result)

    student2 = {
        'id': '20170102',
        'name': 'Mike',
        'age': 21,
        'gender': 'male'
    }
    result = collection.insert_one(student2)
    print(result.inserted_id)


def select_data():
    # 查找数据
    result = collection.find_one({'name': 'Mike'})
    print(type(result))
    print(result)

    results = collection.find({'age': {'$gt': 20}})
    print(results)
    for result in results:
        print(result)


def counts():
    # 计数
    count = collection.count_documents()
    print(count)


def sort():
    # 排序
    results = collection.find().sort('name', pymongo.ASCENDING)
    print([result['name'] for result in results])


def skip():
    # 偏移
    results = collection.find().sort('name', pymongo.ASCENDING).skip(2)
    print([result['name'] for result in results])


def update_data():
    condition = {'name': 'Mike'}
    student = collection.find_one(condition)
    student['age'] = 25
    result = collection.update_one(condition, {'$set': student})
    print(result)
    print(result.matched_count, result.modified_count)


if __name__ == '__main__':
    # 连接MongoDB
    client = pymongo.MongoClient(host='localhost', port=27017)
    # 指定test数据库
    db = client['test']
    # 指定students集合
    collection = db.students
    update_data()
