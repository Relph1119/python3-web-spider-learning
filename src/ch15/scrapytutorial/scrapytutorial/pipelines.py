# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
import pymongo
from scrapy.exceptions import DropItem


class TextPipeline:
    def __init__(self):
        # 限制text长度
        self.limit = 50

    def process_item(self, item, spider):
        if item['text']:
            if len(item['text']) > self.limit:
                item['text'] = item['text'][0:self.limit].rstrip() + '...'
            return item
        else:
            return DropItem('Missing Text')


class MongoDBPipeline:
    def __init__(self, connection_string, database):
        self.connection_string = connection_string
        self.database = database

    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            connection_string=crawler.settings.get('MONGODB_CONNECTION_STRING'),
            database=crawler.settings.get('MONGODE_DATABASE')
        )

    def open_spider(self, spider):
        # spider开启时调用
        self.client = pymongo.MongoClient(self.connection_string)
        self.db = self.client[self.database]

    def process_item(self, item, spider):
        # 执行数据插入
        name = item.__class__.__name__
        self.db[name].insert_one(dict(item))
        return item

    def close_spider(self, spider):
        # spider关闭时调用
        self.client.close()
