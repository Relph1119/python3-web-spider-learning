from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule

from ch15.scrapyuniversaldemo.scrapyuniversaldemo import items, loaders
from ch15.scrapyuniversaldemo.scrapyuniversaldemo.utils import get_config


class UniversalSpider(CrawlSpider):
    name = 'universal'

    def __init__(self, name, *args, **kwargs):
        config = get_config(name)
        self.config = config
        self.start_urls = config.get('start_urls')
        self.allowed_domains = config.get('allowed_domains')
        rules = []
        for rule_kwargs in config.get('rules'):
            link_extractor = LinkExtractor(**rule_kwargs.get('link_extractor'))
            rule_kwargs['link_extractor'] = link_extractor
            rule = Rule(**rule_kwargs)
            rules.append(rule)
        self.rules = rules
        super(UniversalSpider, self).__init__(*args, **kwargs)

    def parse_detail(self, response):
        item = self.config.get('item')
        if item:
            cls = getattr(items, item.get('class'))()
            loader = getattr(loaders, item.get('loader'))(cls, response=response)
            for key, value in item.get('attrs').items():
                for extractor in value:
                    if extractor.get('method') == 'xpath':
                        loader.add_xpath(key, extractor.get('arg'), **{'re': extractor.get('re')})
                    if extractor.get('method') == 'css':
                        loader.add_css(key, extractor.get('arg'), **{'re': extractor.get('re')})
                    if extractor.get('method') == 'value':
                        loader.add_value(key, extractor.get('args'), **{'re': extractor.get('re')})
                yield loader.load_item()

