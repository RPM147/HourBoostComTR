import multiprocessing
import os

bind = "0.0.0.0:5000"
# UYARI: Boost durumu, timer'lar, JWT blacklist, brute-force sayaçları,
# game_cache ve "memory://" rate limiter PROCESS-İÇİ bellekte tutulur.
# Bu yüzden worker sayısı 1 OLMAK ZORUNDADIR. Yatay ölçek (workers>1 veya
# birden fazla sunucu) gerekiyorsa bu durum önce Redis'e taşınmalıdır
# (bkz. FIX.md Phase 4/6). Aksi halde çift loglama ve limit kaçağı olur.
workers = 1
worker_class = "gevent"
worker_connections = 100
timeout = 120
keepalive = 5
# gunicorn 25.x kontrol soketi, gevent altında asyncio'yu ayrı bir thread'de
# çalıştırır; bu, worker boot sırasında aralıklı kilitlenmeye (restart hang)
# yol açabiliyor. Bu özelliği kullanmıyoruz; kapatıyoruz.
control_socket_disable = True
errorlog = "/home/ubuntu/steamboost/logs/error.log"
accesslog = "/home/ubuntu/steamboost/logs/access.log"
loglevel = "info"
