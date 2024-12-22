from threading import Thread,RLock

from inspect import getsource
from utils.download import download
from utils import get_logger
import scraper
import time
import datetime

from urllib.parse import urlparse


class Worker(Thread):
    domain_last_visited = {} # Key=Domain , Value=Time
    politeness_lock = RLock()
    def __init__(self, worker_id, config, frontier):
        self.logger = get_logger(f"Worker-{worker_id}", "Worker")
        self.config = config
        self.frontier = frontier
        self.idle = True
        self.can_quit = False
        # basic check for requests in scraper
        assert {getsource(scraper).find(req) for req in {"from requests import", "import requests"}} == {-1}, "Do not use requests from scraper.py"
        super().__init__(daemon=True)
        
    def run(self):
        while not self.can_quit:
            tbd_url = self.frontier.get_tbd_url()
            if not tbd_url:
                self.logger.info("Frontier is empty. Stopping Crawler.")
                self.idle = True
                time.sleep(0.5) 
                continue
                #break
            self.idle=False
            parsed = urlparse(tbd_url)
            #split_domain = parsed.netloc.split(".")[-2]
            #domain = ".".join(split_domain)
            #print("domain", domain)
            diff = 0
            while diff < self.config.time_delay:
                with Worker.politeness_lock:
                    if parsed.netloc in Worker.domain_last_visited:
                        now = time.time()
                        diff = now - Worker.domain_last_visited[parsed.netloc]
                        if diff < self.config.time_delay:
                            #print(diff, self.config.time_delay, "too fast")
                            time.sleep(0.1)
                    else:
                        diff = self.config.time_delay
            with Worker.politeness_lock:
                resp = download(tbd_url, self.config, self.logger)
                Worker.domain_last_visited[parsed.netloc] = time.time()
            self.logger.info(
                f"Downloaded {tbd_url}, status <{resp.status}>, "
                f"using cache {self.config.cache_server}.")
            scraped_urls = scraper.scraper(tbd_url, resp)
            for scraped_url in scraped_urls:
                self.frontier.add_url(scraped_url)
            self.frontier.mark_url_complete(tbd_url)
            time.sleep(self.config.time_delay)
    
    def is_idle(self):
        #print("idle {}".format(self.idle))
        return self.idle
    
    def quit(self):
        self.can_quit=True
        #print("quit set to {}".format(self.can_quit))