# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class DemoItem(scrapy.Item):
    origin = scrapy.Field()
    headers = scrapy.Field()
    args = scrapy.Field()
    url = scrapy.Field()
