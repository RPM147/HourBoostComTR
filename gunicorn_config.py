import multiprocessing
import os

bind = "0.0.0.0:5000"
workers = 1
worker_class = "gevent"
worker_connections = 100
timeout = 120
keepalive = 5
errorlog = "/home/ubuntu/steamboost/logs/error.log"
accesslog = "/home/ubuntu/steamboost/logs/access.log"
loglevel = "info"
