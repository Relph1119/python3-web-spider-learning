# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

from scrapy import Item, Field


class BookItem(Item):
    name = Field()
    tags = Field()
    score = Field()
    cover = Field()
    price = Field()
