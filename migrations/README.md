# Phase 5H.1B — Güncel kullanım sözleşmesi

İlk baseline `20260907_01` değişmedi; yeni head **`20260908_01`**. Güvenli
`users.is_verified=0`, `users.lang='tr'`, `steam_accounts.is_boosting=0`
server default'ları artık model ve migration'ın açık parçasıdır. Hedef: 9 tablo,
103 kolon, 7 FK, 14 named index ve iki ledger trigger'ı. Dört nullable users
UNIQUE indexi `ux_users_steam_id`, `ux_users_verification_token`,
`ux_users_reset_token`, `ux_users_email_change_token` isimlerini taşır.

Şema başlangıç adımı **yalnız denetler**; tablo yaratmaz, stamp veya legacy veri
backfill'i yapmaz. Ayrı accounting/credential/boost lifecycle recovery işleri
korunur; bunlar bütün startup'ın DML'siz olduğu anlamına gelmez.
`DATABASE_URL` mevcut, nonempty, symlink/junction olmayan
canonical mutlak SQLite dosyasını göstermeli; `DB_SCHEMA_MODE=alembic` olmalıdır.
`mode=rw` bağlantısı eksik dosyanın sessizce yeniden yaratılmasını engeller.
PostgreSQL/Redis ve çok worker hâlâ kapalıdır.

## Yeni kurulum ve salt-okuma denetimi

```bash
# Var olmayan dosya adı kullanın; parent dizini önceden oluşturulmuş olmalı.
python schema_tools.py bootstrap-disposable --sqlite-path /absolute/private/new.sqlite
python schema_tools.py audit --sqlite-path /absolute/private/new.sqlite
```

Bootstrap boş DB'de baseline→head zincirini çalıştırır; head'in tablo rebuild'i
yalnız tüm uygulama tabloları boşken mümkündür. Mevcut/populated dosyada bu yol
reddedilir. Audit şema, revision, integrity/FK/ledger yanında timestamp/storage
class, ödeme/oturum/plan ve history backfill önkoşullarını da salt-okunur denetler.
Rapor sadece sabit alan adları ve sayımlar içerir; `stamp_permitted=false` genel
stamp yetkisinin kapalı olduğunu belirtir, bir adoption komutu yerine geçmez.

## Tanınan historical SQLite'ı sahiplenme (offline adoption)

1. Bakım modunu açın; uygulamayı ve diğer DB writer'larını durdurun. Sadece web
   bakım sayfası yeterli değildir. Servisin kendi kendine açılmasına yol açabilecek
   restart/watch işlemlerini bakım penceresinde kontrol altında tutun.
2. SQLite backup API ile **bağımsız**, tutarlı ve owner-only (`0600`) bir yedek
   oluşturun; source/env yedeklerini de alın. Canlı WAL dosyasını tek başına
   `cp` ederek yedek kabul etmeyin. Önce kopyada adoption ve restore provası yapın.
3. Yeni tool ile audit çalıştırın. Tanınan farklar yalnız eksik dört UNIQUE/index
   olmalıdır; diğer farklar veya legacy-data kontrolleri durdurucu sebep sayılır.
   Rapordaki `schema_fingerprint` değerini kaydedin.
4. Yalnız bu kabulden sonra aşağıdaki komutu kullanın:

```bash
python schema_tools.py adopt-sqlite \
  --sqlite-path /absolute/private/live.sqlite \
  --backup-path /absolute/private/backup.sqlite \
  --expect-fingerprint <audit-schema-fingerprint> \
  --confirm-maintenance
```

Araç `BEGIN EXCLUSIVE` içinde kaynağı tekrar denetler; yedeğin tüm uygulama
satırları/kolonları ve şemasını kaynakla karşılaştırır. Yalnız dört exact UNIQUE
index eklenebilir. Şema ve veri uygunluğu doğrulandıktan sonra aynı transaction
içinde head stamp edilir. Tüm tablo logical digest'leri korunmazsa rollback olur.
Yanlış isimli/tanımlı indexler değiştirilmez; beklenmeyen revision/şema veya
duplicate/legacy eksikleri otomatik temizlenmez. Hard-link source/yedek reddedilir.
Zaten doğrulanmış head'de çağrı no-op döner. Bu komut genel migration motoru değildir.

5. Source/config birlikte aktive edilir; `DATABASE_URL` mutlak canlı yolu,
   `DB_SCHEMA_MODE=alembic` olmalıdır. Servis tam restart ile açılır. Salt-okunur
   audit, veri sayım/digest/ledger, local/public cevaplar ve yeni loglar doğrulanır.
6. Geri dönüşte source/env ve DB revision uyumu birlikte değerlendirilir.
   Bu adoption uygulama satırı değiştirmez; eski runtime sürümüne acil source/env
   dönüşü dört ek UNIQUE ile uyumlu olsa da önce prova edilmelidir. Yeni yazma
   başladıktan sonra eski DB yedeğini körlemesine restore etmeyin. Downgrade kapalıdır.

`flask db` kullanmayın; app importu background işleri başlatır. Generic Alembic
CLI stamp/upgrade/offline yolları kapalıdır. Araçlar app/config/dotenv yüklemez.
Emekliye ayrılan runtime bridge yalnız test fixture'ında tarihsel regresyon için
korunur; eksik legacy veri için ayrı reviewed offline veri migration'ı gerekir.

## 5H.1A tarihsel kayıt (aşağıdaki sınırlamalar o kabul anına aittir)

Üstteki 5H.1B sözleşmesi günceldir; aşağıdaki bölüm önceki checkpoint'i açıklar.

Bu altyapı `app.py` veya `config.py` yüklemez; `.env` okumaz, Steam/payment
worker başlatmaz. Baseline revision: `20260907_01`. Mevcut production DB'ye
`stamp`, `upgrade`, tablo rebuild veya veri düzeltmesi **bu phase'te yoktur**.

## Güvenli komutlar

Kurulu uygulama Python ortamını ve `requirements.txt` bağımlılıklarını kullanın.
Alembic `1.19.1` ve Mako `1.4.1` production'daki mevcut sürümlere sabitlendi;
bu pinler bir production dependency upgrade'i gerektirmez.

```bash
cd /home/ubuntu/steamboost
.venv-current/bin/python schema_tools.py audit \
  --sqlite-path /home/ubuntu/steamboost/instance/steamboost.db
```

Salt-okuma audit, SQLite `mode=ro`, `query_only=ON`, FK kontrolü ve tek açık
read transaction kullanır. WAL'daki commit edilmiş veriyi okur; canlı DB için
`immutable=1` kullanılmaz. SQLite'ın shared-memory/WAL koordinasyon davranışı
nedeniyle bu bir dosya sistemi adli-imaj garantisi değil, DB'ye DDL/DML
yazılmaması garantisidir. Sabit delil gerekiyorsa önce SQLite backup API ile
tutarlı kopya alın ve aynı audit'i kopyaya uygulayın.

Yeni, boş bir deneme DB'si oluşturmak için:

```bash
rehearsal_dir=$(mktemp -d /tmp/hourboost-schema-rehearsal.XXXXXX)
.venv-current/bin/python schema_tools.py bootstrap-disposable \
  --sqlite-path "$rehearsal_dir/rehearsal.sqlite"
```

Hedef dosya daha önce bulunmamalıdır; sıfır baytlık mevcut dosya da reddedilir.
Araç önce kendi özel dizininde DB'yi oluşturup denetler, sonra aynı dosya
sisteminde atomik hard-link ile yayınlar. Hedef arada oluşturulursa işlem
başarısız olur, mevcut dosya korunur. Hard-link desteklemeyen dosya sistemlerinde
güvensiz overwrite/copy fallback yapılmaz. Bu komut yalnız yeni prova dosyasını
yazar; `operation=bootstrap_disposable`, `read_only=false` olarak raporlar.

Göreli, symlink/junction üzerinden yönlenen, eksik veya boş audit hedefleri
reddedilir. URL, `.env` veya çalışma dizininden DB seçimi yapılmaz. Windows'ta da
tam canonical dosya yolu verilmelidir. Proje kökündeki boş `steamboost.db`,
Flask'ın `instance/steamboost.db` dosyası değildir.

Çıkış kodları:

- `0`: İncelenen şema hedefle uyumlu ve uygulanan veri kontrolleri geçti.
- `1`: Şema/metadata/veri/revision farkı bulundu; raporu inceleyin.
- `2`: Yol, dependency, izin, DB okuma veya işlem hatası; hassas exception metni
  yerine sabit `schema_operation_failed` döner.

Her sonuçta `stamp_permitted=false` kalır. Başarılı audit **otomatik migration
onayı değildir**. Mevcut DB'ye `stamp` uygulayabilmek için 5H.1B kabulü gerekir.
Audit bulgularını production startup içine eklemedik; mevcut eksiklikler yüzünden
çalışan servisi istemeden durdurmaz.

## Dondurulmuş hedef sözleşme

- 9 uygulama tablosu, 103 kolon, 7 FK; FK'lere yeni CASCADE eklenmez.
- 10 named index: ORM'deki beş index ve runtime'ın beş ödeme indexi.
- `ux_payments_match_token`, `ux_payments_transaction_id` ve
  `ux_payments_one_open_checkout` partial UNIQUE koşulları aynen korunur.
- `users` içinde username/email ve dört nullable Steam/token unique kuralı.
- Finansal/audit/snapshot alanlarının nullable ve FK olmayan tasarımı korunur.
- `boost_logs` CHECK ile iki integer-storage-class denetleyen ledger trigger'ı.
- ORM `default=` değerleri server default'a çevrilmez. Yeni baseline'da yalnız
  `payments.admin_hidden` ve `verification_attempts` DB server default taşır.
- Baseline değişebilir `models`, `time_utils` veya runtime migration yardımcılarını
  import etmez. DDL bir kez autogenerate edilip elle incelendi ve sabitlendi.
  Metadata parity için yalnız güvenli `models` tanımları ayrı geçici DB'ye yüklenir.

Audit; kolon/type/nullability/default/PK, FK anahtarları ve aksiyonları, unique
key'ler, index kolon sırası/collation/DESC/unique/predicate ve trigger tanımını
karşılaştırır. PRAGMA'nın göstermediği table DDL özellikleri (`ON CONFLICT`,
`DEFERRABLE`, `COLLATE`, `AUTOINCREMENT`, `WITHOUT ROWID`, vb.) de denetlenir.
SQLite çift tırnaklı string davranışı nedeniyle quoted SQL tokenları aynen
korunur. Biçimsel olarak eşdeğer ama farklı quoting/DDL özelikleri ihtiyatlı
olarak fark sayılabilir; araç bu farkları otomatik düzeltmez veya onaylamaz.

Veri raporu yalnız integrity/FK sonuçları, dört nullable user unique alanındaki
duplicate grup sayıları ve ledger invalid/legacy satır sayıları/toplamları
içerir. Token, hesap, e-posta veya satır değerleri yazdırılmaz. Ledger toplamları
SQLite `SUM` yerine Python integer ile biriktirilir. Bu kontroller plan/session/
payment backfill ve UTC veri provası gibi 5H.1B/1C kapılarının tamamı değildir.

## Bilinen historical SQLite farkları

2026-09-05 salt-okuma canlı şema incelemesinde:

- `users.steam_id`, `verification_token`, `reset_token`, `email_change_token`
  UNIQUE kısıtları fiziksel olarak yoktu. Bunlar blocking schema drift'tir.
  Mevcut token üretimi 256-bit rastgelelik kullanır; Steam ilk kaydındaki
  deterministic e-posta + email UNIQUE ek koruma sağlar. Sırf constraint eksikliği
  aktif hesap ele geçirme kanıtı değildir; duplicate kontrolü yine zorunludur.
- `users.is_verified/lang` ve `steam_accounts.is_boosting` eski server default
  taşır. Dış writer davranışını etkileyebileceği için sessizce eşdeğer sayılmaz.
- INTEGER `payments.verification_attempts` için `DEFAULT 0` ve `DEFAULT '0'`
  aynı SQLite stored integer üretir; bu dar fark compatibility note'tur.
- `payments.status VARCHAR(20)`, `match_token VARCHAR(32)` ve bazı kullanıcı
  token/e-posta alanlarının TEXT deklarasyonları bilinen legacy tiplerdir.
  SQLite uzunluk zorlamadığı için açık allowlist ile compatibility note üretilir;
  bu deklarasyonlar PostgreSQL'e aynen taşınamaz.
- Eski BoostLog tablosunda named CHECK bulunmayabilir. İki tam doğru ledger
  trigger'ı mevcutsa eksik CHECK compatibility note'tur; trigger yalnız adı
  tuttuğu için kabul edilmez. Yanlış/eksik trigger her zaman drift'tir.
- Inline `payments.transaction_id` UNIQUE olmaması, doğru nullable partial
  UNIQUE index varsa semantik olarak karşılanır; iki yapıyı zorla çoğaltmak gerekmez.

Bu phase tarihsel DB'yi hedefe benzetmek için yeniden oluşturmaz. 5H.1B önce
backup/kopya üzerinde gerekli unique/default kararlarını ve data önkoşullarını
doğrulamalı, ardından onaylı migration + stamp yapmalıdır.

## Aktivasyon ve geri dönüş sınırları

`alembic heads/history` yalnız repository bilgisi için kullanılabilir.
`flask db` kullanmayın: Flask CLI app importu legacy startup DDL ve background
servisleri çalıştırır. Standalone env'de URL fallback yoktur; doğrudan Alembic
`stamp/upgrade/downgrade` veya offline SQL komutları reddedilir. Programmatik
bootstrap da tamamen boş, açık transaction içindeki SQLite bağlantısı ister.

PostgreSQL bu baseline tarafından desteklenmez; revision/CLI ve runtime gate
5H.1C kabulüne kadar kapalıdır. SQLite zamanları naive UTC/DATETIME kalır;
PostgreSQL hedefi TIMESTAMPTZ/aware UTC olup integer genişlikleri, unique/type
uyumu ve gerçek veri taşıma testi 5H.1C'ye aittir. Redis ve multi-worker açılmaz.

Baseline downgrade finansal kayıtları silen DROP üretmez; daima reddedilir.
Bu phase'in source rollback'i eski dosyaları geri yüklemektir; canlı DB migration
almadığı için DB restore gerekmez. Gerçek migration sonrasında kör DB rollback
yerine ayrıca doğrulanmış restore/veri birleştirme planı gerekir.

Kaynaklar: [Alembic connection sharing](https://alembic.sqlalchemy.org/en/latest/cookbook.html#sharing-a-connection-across-one-or-more-programmatic-migration-commands),
[autogenerate sınırları](https://alembic.sqlalchemy.org/en/latest/autogenerate.html),
[SQLAlchemy SQLite transaction ve URI davranışı](https://docs.sqlalchemy.org/en/20/dialects/sqlite.html).
