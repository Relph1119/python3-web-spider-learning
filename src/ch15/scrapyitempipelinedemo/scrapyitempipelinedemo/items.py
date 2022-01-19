# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class MovieItem(scrapy.Item):
    name = scrapy.Field()
    categories = scrapy.Field()
    score = scrapy.Field()
    drama = scrapy.Field()
    directors = scrapy.Field()
    actors = scrapy.Field()
