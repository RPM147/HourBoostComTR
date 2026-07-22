# HourBoost

HourBoost, bir kullanıcının bir veya daha fazla Steam hesabında seçtiği oyunları
çalışıyor gösteren; süre, plan, ödeme ve yönetim akışlarını tek Flask uygulamasında
yöneten bir servistir. Arayüz Türkçe ve İngilizce çalışır.

## Mimari

- `app.py`: Flask API, oturumlar, kota scheduler'ı, Shopier akışı ve admin paneli.
- `steam_manager.py`: hesap/run yaşam döngüsü, gevent koordinasyonu, crash-durable
  pending segmentler ve Node worker IPC istemcisi.
- `steam_worker.js`: `steam-user@5.3.0` kullanan Steam CM worker'ı. Python ile
  `stdin/stdout` üzerinden satır bazlı JSON mesajlarıyla konuşur.
- `models.py`: SQLAlchemy modelleri ve kalıcı denetim kayıtları.
- `payment_verification.py` / `shopier.py`: Shopier API doğrulama ve retry akışı.

Her aktif Steam hesabı için ayrı bir Node worker process'i açılır. Bu, hesap
izolasyonu sağlar fakat yüksek hesap sayısında RAM maliyeti yaratır. Tek supervisor
ve shard/multiplex mimarisi [PHASE_ROADMAP.md](PHASE_ROADMAP.md) Phase 5I kapsamıdır.

## Çalışma sözleşmeleri

### Steam

- İlk giriş, Steam Guard e-posta veya authenticator kodu isteyebilir.
- Başarılı girişten sonra parola/refresh token Fernet ile şifrelenerek hesap bazlı
  state dizininde tutulur. Üretimde bağımsız ve kalıcı `CRED_KEY` zorunlu kabul
  edilmelidir.
- Çalışan servis içindeki geçici bağlantı kopmalarında generation/CAS korumalı
  reconnect denenir.
- Servis restartından sonra otomatik Steam login veya boost resume **yoktur**.
  Bu bilinçli ürün kararıdır; startup reconciliation bayat DB boost durumunu temizler.

### Kota

Plan limitleri kullanıcı başına toplam **boost-account-saniyesi** olarak ölçülür.
Kalan kullanım `R`, aktif hesap sayısı `N` ise tahmini kalan duvar süresi `R / N`
olur. Kullanıcı başına tek generation'lı watchdog bulunur. Günlük/toplam sınırda
hard fence yeni start/resume işlemlerini engeller, açık segmentleri ortak mutlak
deadline'da kapatır ve gerçek Steam kapanış zamanını `remote_stopped_at` alanında
ayrı denetim izi olarak saklar. Günlük pencere UTC'dir.

### Ödeme

- Plan butonu yalnız benzersiz, yüksek entropili bir `HB-...` checkout kodu üretir;
  ödeme yapılmış sayılmaz.
- İmzalı Shopier webhook'u olayı kuyruğa alır. Plan aktivasyonunun otoritesi webhook
  gövdesi değil, `SHOPIER_PAT` ile Shopier API'den doğrulanan sipariş durumudur.
- API doğrulaması belirsiz veya başarısızsa ödeme otomatik onaylanmaz; retry/manual
  review akışında kalır.
- Kontrollü gerçek ödeme kabul testi tamamlanana kadar operasyonel durum ve açık
  maddeler [PAYMENT_PLAN.md](PAYMENT_PLAN.md) belgesindedir.

## Güvenlik özeti

- DB-backed, iptal edilebilir web oturumları ve CSRF koruması.
- PBKDF2-SHA256 parola hash'i, login timing eşitlemesi ve brute-force limiti.
- Steam kimlik bilgilerinde Fernet at-rest şifreleme ve hesap bazlı özel dizinler.
- Shopier webhook imza kontrolü, account/webhook kimliği doğrulaması, PAT API
  doğrulaması ve idempotent transaction eşleştirmesi.
- SSRF korumalı URL açma/redirect akışı, güvenilir proxy IP sözleşmesi ve tek satır
  log sanitization.
- E-posta aksiyon tokenları URL path'ine yazılmaz; fragment + CSRF korumalı POST
  kullanılır ve token sayfaları `no-referrer` uygular.
- Uygulama istek gövdesi varsayılan olarak 512 KiB ile sınırlıdır. Nginx de
  `client_max_body_size 512k;` kullanmalıdır.

## Gereksinimler

- Python 3.11 veya daha yeni
- Node.js 14 veya daha yeni ve npm (`npm ci` için)
- Linux production'da Gunicorn + gevent
- Steam Web API anahtarı
- E-posta ve ödeme özellikleri kullanılacaksa ilgili SMTP/Shopier bilgileri

## Yerel kurulum

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
npm ci
cp .env.example .env
```

`.env` içindeki en az `SECRET_KEY`, `STEAM_API_KEY` ve üretimde `CRED_KEY`
değerlerini doldurun. Shopier otomatik doğrulamasını açmadan önce PAT, webhook
secret, account ID ve webhook ID alanlarının tamamını yapılandırın.

Geliştirme sunucusu:

```bash
python app.py
```

Production örneği:

```bash
gunicorn -c gunicorn_config.py app:app
```

## Test ve bağımlılık kontrolü

```bash
python -m py_compile app.py models.py config.py steam_manager.py shopier.py payment_verification.py
node --check steam_worker.js
python -m unittest discover -s tests -p 'test_*.py'
python -m pip check
npm audit --omit=dev --audit-level=low
```

## Production sınırları

- Gunicorn `workers = 1` kalmalıdır. Scheduler, manager registry, bazı güvenlik
  sayaçları ve `memory://` limiter process içi durum taşır. Redis/PostgreSQL ve
  Steam ownership ayrıştırılmadan worker sayısını artırmak limit kaçağı ve çift
  işlem üretir; geçiş Phase 5H–5I kapsamındadır.
- Gunicorn yalnız `127.0.0.1:5000` üzerinde dinlemelidir. Public trafik TLS
  sonlandıran nginx/Cloudflare katmanından gelmelidir.
- `.env`, SQLite DB, `tokens/`, `sentry/`, `logs/`, Node hesap state'i ve credential
  dizinleri source deploy ile ezilmemeli; ayrı yedeklenmelidir.
- SQLite'taki mevcut legacy FK borcu Phase 5F'te temizlenecektir. Yeni deploy FK
  ihlal sayısını artırmamalıdır.

## Belgeler

- [PHASE_ROADMAP.md](PHASE_ROADMAP.md): phase kapsamı, kabul kapıları ve rolloutlar.
- [PAYMENT_PLAN.md](PAYMENT_PLAN.md): hibrit Shopier güven modeli ve canlı kabul.
- [HOURBOOST_MEMORY.md](HOURBOOST_MEMORY.md): geçmiş incident ve uygulama notları.

## Lisans

GNU Affero General Public License v3.0 (AGPL-3.0). Ayrıntı için [LICENSE](LICENSE).
