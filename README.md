# ⚡ HourBoost

Steam oyun saati boost servisi. Birden fazla Steam hesabını yönetin, oyun saatlerinizi otomatik olarak artırın.

---

## 🚀 Özellikler

- 🎮 Birden fazla Steam hesabı desteği
- ⏱️ Zamanlayıcılı boost (X saat boost yap, sonra dur)
- 📊 Oyun başına boost istatistikleri
- 🔒 E-posta doğrulama sistemi
- 🔑 Şifre sıfırlama
- 💳 Shopier ile otomatik ödeme entegrasyonu
- 🛡️ Brute force koruması
- 📱 Aktif oturum yönetimi (IP ve cihaz bilgisiyle)
- 👤 Admin paneli (kullanıcı yönetimi, ödeme onaylama, duyurular)
- 🌙 Otomatik yeniden bağlantı (bağlantı kopunca)

---

## 📋 Gereksinimler

- Python 3.10+
- pip

---

## ⚙️ Kurulum

1. Repoyu klonla

git clone https://github.com/kullanici/hourboost.git
cd hourboost

2. Sanal ortam oluştur

python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

3. Bağımlılıkları yükle

pip install -r requirements.txt

4. Ortam değişkenlerini ayarla

cp .env.example .env
nano .env

.env dosyasını kendi bilgilerinle doldur:

SECRET_KEY=guclu-rastgele-bir-anahtar
DATABASE_URL=sqlite:///steamboost.db
MAIL_USERNAME=ornek@gmail.com
MAIL_PASSWORD=gmail-app-sifresi
MAIL_FROM=ornek@gmail.com
SITE_URL=https://siteadresi.com
SHOPIER_PAT=shopier-api-tokeni
SHOPIER_WEBHOOK_SECRET=webhook-gizli-anahtari
SHOPIER_BASIC_PRODUCT_ID=urun-id
SHOPIER_PREMIUM_PRODUCT_ID=urun-id
CRED_KEY=fernet-anahtari

Not: Gmail kullanıyorsanız normal şifre değil, App Password oluşturmanız gerekir.

5. Çalıştır

python app.py

Prodüksiyon (Gunicorn):
gunicorn -c gunicorn.conf.py app:app

🛡️ Güvenlik
Steam şifreleri Fernet ile şifrelenmiş olarak saklanır
JWT token blacklist sistemi
IP ve kullanıcı bazlı brute force koruması (5 başarısız girişte 5 dakika kilit)
E-posta doğrulama zorunluluğu
CSRF koruması
SQL Injection koruması (SQLAlchemy ORM)
Shopier webhook imza doğrulaması

🗂️ Proje Yapısı

hourboost/
├── app.py              # Ana uygulama, tüm endpoint'ler
├── models.py           # Veritabanı modelleri
├── config.py           # Yapılandırma
├── mailer.py           # E-posta gönderme
├── shopier.py          # Shopier ödeme entegrasyonu
├── steam_manager.py    # Steam bağlantı yönetimi
├── gunicorn.conf.py    # Gunicorn yapılandırması
├── templates/          # HTML şablonları
├── static/             # Statik dosyalar (CSS, JS, favicon)
├── .env.example        # Örnek ortam değişkenleri
└── requirements.txt    # Python bağımlılıkları

🔧 Ortam Değişkenleri

Değişken	Açıklama	Zorunlu

SECRET_KEY	Flask gizli anahtarı
DATABASE_URL	Veritabanı bağlantı adresi (SQLite varsayılan)
MAIL_USERNAME	Gmail adres
MAIL_PASSWORD	Gmail App Password	
MAIL_FROM	Gönderici mail adresi
SITE_URL	Sitenin tam adresi	
SHOPIER_PAT	Shopier API token	
SHOPIER_WEBHOOK_SECRET	Shopier webhook gizli anahtarı	
SHOPIER_BASIC_PRODUCT_ID	Basic plan ürün ID	
SHOPIER_PREMIUM_PRODUCT_ID	Premium plan ürün ID	
CRED_KEY	Steam şifre şifreleme anahtarı

🛡️ Güvenlik
Steam şifreleri Fernet ile şifrelenmiş olarak saklanır
JWT token blacklist sistemi
IP ve kullanıcı bazlı brute force koruması (5 başarısız girişte 5 dakika kilit)
E-posta doğrulama zorunluluğu
CSRF koruması
SQL Injection koruması (SQLAlchemy ORM)
Shopier webhook imza doğrulaması

⚠️ Yasal Uyarı
Bu yazılım yalnızca eğitim amaçlıdır. Steam'in Kullanım Koşulları'na aykırı kullanımdan doğacak sorumluluk kullanıcıya aittir.


