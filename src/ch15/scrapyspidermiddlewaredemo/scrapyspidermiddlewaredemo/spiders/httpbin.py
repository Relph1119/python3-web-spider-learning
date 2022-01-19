import scrapy
from scrapy import Request

from ch15.scrapyspidermiddlewaredemo.scrapyspidermiddlewaredemo.items import DemoItem


class HttpbinSpider(scrapy.Spider):
    name = 'httpbin'
    allowed_domains = ['www.httpbin.org']
    start_url = 'https://www.httpbin.org/get'

    def start_requests(self):
        for i in range(5):
            url = f'{self.start_url}?query={i}'
            yield Request(url, callback=self.parse)

    def parse(self, response):
        item = DemoItem(**response.json())
        print('Status:', response.status)
        yield item
