#!/usr/bin/env python
# encoding: utf-8
"""
@author: HuRuiFeng
@file: mysql_oper_demo.py
@time: 2022/1/5 19:31
@project: python3-web-spider-learning
@desc: 4.4 MySQL存储（P138~P144）
"""
import pymysql


def connect_mysql():
    db = pymysql.connect(host='localhost', user='root', password='123456', port=3306)
    cursor = db.cursor()
    cursor.execute('select version()')
    data = cursor.fetchone()
    print('Database version:', data)
    cursor.execute("create database spiders default character set utf8mb4")
    db.close()


def create_table():
    db = pymysql.connect(host='localhost', user='root', password='123456', port=3306, db='spiders')
    cursor = db.cursor()
    sql = """
        create table if not exists students (
            id varchar(255) not null,
            name varchar(255) not null,
            age int not null,
            primary key (id))
        """
    cursor.execute(sql)
    db.close()


def insert_data():
    id = '20120001'
    user = 'Bob'
    age = 20

    db = pymysql.connect(host='localhost', user='root', password='123456', port=3306, db='spiders')
    cursor = db.cursor()
    sql = 'insert into students(id, name, age) values(%s, %s, %s)'
    try:
        cursor.execute(sql, (id, user, age))
        db.commit()
    except:
        db.rollback()
    db.close()


def insert_dict_data():
    db = pymysql.connect(host='localhost', user='root', password='123456', port=3306, db='spiders')
    cursor = db.cursor()

    data = {
        'id': '20120001',
        'name': 'Bob',
        'age': 20
    }
    table_name = 'students'
    keys = ','.join(data.keys())
    values = ','.join(['%s'] * len(data))
    sql = "insert into {table}({keys}) values({values})".format(table=table_name, keys=keys, values=values)
    try:
        cursor.execute(sql, tuple(data.values()))
        db.commit()
    except:
        db.rollback()
    db.close()


def update_dict_data():
    db = pymysql.connect(host='localhost', user='root', password='123456', port=3306, db='spiders')
    cursor = db.cursor()

    data = {
        'id': '20120001',
        'name': 'Bob',
        'age': 21
    }
    table_name = 'students'
    keys = ','.join(data.keys())
    values = ','.join(['%s'] * len(data))

    sql = "insert into {table}({keys}) values({values}) on duplicate key update ".format(table=table_name,
                                                                                         keys=keys, values=values)
    update = ','.join(["{key}=%s".format(key=key) for key in data])
    sql += update
    try:
        if cursor.execute(sql, tuple(data.values()) * 2):
            print('Successful')
            db.commit()
    except Exception as e:
        print('Failed:', e)
        db.rollback()
    db.close()


def delete_data():
    db = pymysql.connect(host='localhost', user='root', password='123456', port=3306, db='spiders')
    cursor = db.cursor()

    table_name = 'students'
    condition = 'age > 20'

    sql = 'delete from {table} where {condition}'.format(table=table_name, condition=condition)
    try:
        cursor.execute(sql)
        db.commit()
    except:
        db.rollback()
    db.close()


if __name__ == '__main__':
    delete_data()
