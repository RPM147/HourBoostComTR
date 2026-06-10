import multiprocessing
import os

bind = "0.0.0.0:5000"
# UYARI: Boost durumu, timer'lar, JWT blacklist, brute-force sayaçları,
# game_cache ve "memory://" rate limiter PROCESS-İÇİ bellekte tutulur.
# Bu yüzden worker sayısı 1 OLMAK ZORUNDADIR. Aksi halde çift loglama ve
# limit kaçağı olur.
#
# Yatay ölçek (workers>1 veya birden fazla sunucu) için önce şu durum Redis'e
# taşınmalıdır (bkz. ISSUES.md #15):
#   - JWT blacklist (_token_blacklist set)      -> Redis Set
#   - brute-force sayaçları (_failed_logins)    -> Redis (TTL'li key)
#   - game_cache                                -> Redis (TTL'li key)
#   - rate limiter storage                      -> LIMITER_STORAGE_URI=redis://...
#   - boost manager/timer durumu                -> kalıcı koordinasyon katmanı
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
