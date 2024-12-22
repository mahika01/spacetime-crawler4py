from utils import get_logger
from crawler.frontier import Frontier
from crawler.worker import Worker
import time

class Crawler(object):
    def __init__(self, config, restart, frontier_factory=Frontier, worker_factory=Worker):
        self.config = config
        self.logger = get_logger("CRAWLER")
        self.frontier = frontier_factory(config, restart)
        self.workers = list()
        self.worker_factory = worker_factory

    def start_async(self):
        self.workers = [
            self.worker_factory(worker_id, self.config, self.frontier)
            for worker_id in range(self.config.threads_count)]
        for worker in self.workers:
            worker.start()

    def start(self):
        self.start_async()
        self.join()

    def join(self):
        print("Num workers {}".format(len(self.workers)))
        while True:
            all_threads_idle = True
            time.sleep(0.5)
            for worker in self.workers:
                all_threads_idle = all_threads_idle and worker.is_idle()
            if all_threads_idle:
                for worker in self.workers:
                    worker.quit()
                break
        for worker in self.workers:
            worker.join()
