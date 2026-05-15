<div align="center">

# NetConfig AI

**Cisco IOS konfigürasyonları için akıllı network audit & güvenlik tarayıcısı**

`.txt` / `.cfg` dosyalarını saniyeler içinde analiz eder; **79 kural** çalıştırır, **secret scanner** ile açıkta kalan parolaları yakalar ve her bulgu için aksiyon odaklı öneri üretir.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952B3?logo=bootstrap&logoColor=white)](https://getbootstrap.com/)
[![License](https://img.shields.io/badge/license-MIT-22c55e)]()
[![Rules](https://img.shields.io/badge/Rules-79-4f46e5)]()
[![Vendor](https://img.shields.io/badge/Vendor-Cisco%20IOS%2FIOS%20XE-005073)]()

</div>

---

> **Not:** Bu sürüm yalnızca **Cisco IOS / IOS XE** konfigürasyonlarını analiz eder. NX-OS, Arista EOS, Juniper Junos ve diğer vendor'lar için destek yol haritasındadır.
>
> Proje aktif geliştirme aşamasındadır; yeni kurallar ve LLM entegrasyonu için sürekli güncellenmektedir.

---

## İçindekiler

- [Genel Bakış](#genel-bakış)
- [Öne Çıkan Özellikler](#öne-çıkan-özellikler)
- [Teknoloji Stack'i](#teknoloji-stacki)
- [Mimari](#mimari)
- [Klasör Yapısı](#klasör-yapısı)
- [Kurulum](#kurulum)
- [Çalıştırma](#çalıştırma)
- [Configuration Diff Analizi](#configuration-diff-analizi)
- [Kural Seti](#kural-seti)
- [Yapay Zeka Entegrasyonu](#yapay-zeka-entegrasyonu)
- [Yol Haritası](#yol-haritası)
- [Katkı](#katkı)
- [İletişim](#iletişim)

---

## Genel Bakış

NetConfig AI, kurumsal network mühendislerinin **konfigürasyon denetimi**, **uyumluluk kontrolü** ve **risk analizi** süreçlerini otomatize etmek için tasarlanmıştır.

Mimari üç ana katmandan oluşur:

| Katman | Görev |
|--------|-------|
| **Parser** | Cisco IOS söz dizimini regex + state machine ile yapısal veri modeline çevirir |
| **Rule Engine** | 79 ayrı kuralı çalıştırarak güvenlik / operasyon / uyumluluk bulguları üretir |
| **Secret Scanner** | Açıkta kalan parola / key'leri tespit eder ve otomatik maskeler |
| **Recommendation Layer** | Her bulgu için aksiyon odaklı, best-practice referanslı öneri üretir |

Bu mimari sayesinde sonuçlar **deterministik** (aynı config → aynı bulgu), **denetlenebilir** ve **üretim güvenli**dir.

---

## Öne Çıkan Özellikler

### Analiz & Denetim
- **79 hazır kural** (`R001..R079`) — security, routing, L2, compliance, operations
- **5 severity seviyesi**: `critical`, `high`, `medium`, `low`, `info`
- **5 kategori filtresi**: tek tıkla bulguları daraltma
- Her bulgu için **aksiyon odaklı öneri metni**
- Bulgular severity'ye göre otomatik sıralanır (`critical` → `info`)

### Secret / Credential Tarama
- Cisco **Type 7** ve **Type 0 (cleartext)** parolaları
- **TACACS+ / RADIUS / BGP / OSPF / ISAKMP** key'leri (cleartext)
- Otomatik **maskeleme** — gerçek değer hiçbir zaman ekrana basılmaz
- IPv4 adresleri için son octet maskelemesi (rapor paylaşımı için)

### Vendor / Platform Fingerprinting
- **Çoklu vendor imzası**: Cisco IOS dışında NX-OS, Junos, Huawei, FortiOS, PAN-OS vb. için erken uyarı
- Platform modeli (ISR, ASR, Catalyst, Nexus, ASR9k …)
- OS sürümü ve boot image otomatik çıkarımı

### Configuration Diff
- İki config dosyasını yan yana karşılaştırır
- **Değiştirilen satırlar** (eski → yeni eşleşmeli)
- **Eklenen / Silinen** satırlar (parent + child gruplaması ile hiyerarşik)
- **Yeni oluşan riskler** ve **çözülen riskler** ayrı listeler halinde
- Vendor / hostname / cihaz türü uyumsuzluğunda **otomatik uyarı**

### Raporlama & UI
- **HTML rapor** — paylaşılabilir, basılabilir
- **PDF rapor** — yönetici sunumları için A4 formatı, footer / sayfa numaralı
- **Light / Dark mode** — kullanıcı seçimi `localStorage`'da kalıcı
- Modern Flask + Bootstrap arayüzü, network temalı animasyonlu hero
- POST-Redirect-GET pattern — sayfa yenilemede yeniden gönderim olmaz
- **Input validation** — boş veya non-Cisco IOS dosyalar baştan reddedilir

### Geliştirici Deneyimi
- Tek dosya **CLI** desteği (JSON çıktı opsiyonu)
- Dataclass tabanlı **tip güvenli** modeller
- Regex + state machine ile **bağımlılığı az** parser
- Yeni kural eklemek **30 satırdan kısa** — kategoriler haritası ve `run_rules()` dışında dokunulacak başka yer yok

---

## Teknoloji Stack'i

### Backend
| Teknoloji | Sürüm | Kullanım Amacı |
|-----------|:-----:|----------------|
| [Python](https://www.python.org/) | 3.10+ | Çekirdek dil |
| [Flask](https://flask.palletsprojects.com/) | 3.x | Web framework |
| [Jinja2](https://jinja.palletsprojects.com/) | (Flask ile) | Template engine |
| [xhtml2pdf](https://github.com/xhtml2pdf/xhtml2pdf) | 0.2.16+ | HTML → PDF dönüşümü |
| `dataclasses` | stdlib | Yapısal veri modelleri |
| `re` | stdlib | Cisco IOS söz dizimi parse |
| `difflib` | stdlib | Config diff (SequenceMatcher) |
| `secrets` / `uuid` | stdlib | Token üretimi |
| `collections.OrderedDict` | stdlib | FIFO eviction cache |

### Frontend
| Teknoloji | Kullanım Amacı |
|-----------|----------------|
| [Bootstrap 5.3](https://getbootstrap.com/) | Grid, formlar, utility class'lar |
| HTML5 / CSS3 | Custom property tabanlı tema sistemi (light / dark) |
| Vanilla JavaScript | Kategori filtreleme, dark mode toggle, partikül animasyon |
| Canvas API | Hero bölümünün animasyonlu network partikül arka planı |
| [Inter](https://rsms.me/inter/) | Sans-serif font |
| [JetBrains Mono](https://www.jetbrains.com/lp/mono/) | Code / diff için monospace font |

### Mimari Prensipler
- **Separation of concerns**: parser, kurallar, öneriler, web tamamen ayrı modüller
- **Deterministik analiz**: rastgelelik / network çağrısı yok, aynı girdi → aynı çıktı
- **Stateless service layer**: `audit_config_text` ve `audit_config_diff` saf fonksiyon
- **Session-free web**: client'a güvenli token döner; sunucuda kısa ömürlü `OrderedDict` cache

---

## Mimari

```text
┌─────────────────────────────────────────────────────────────────┐
│                       Config File (.txt / .cfg)                │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
            ┌──────────────────────────────────────┐
            │   Validation Layer                   │
            │   (vendor detection, IOS markers)    │
            └──────────────────┬───────────────────┘
                               │
                               ▼
            ┌──────────────────────────────────────┐
            │   Parser (regex + state machine)     │
            │   - interfaces, ACL, OSPF, BGP, ... │
            └──────────────────┬───────────────────┘
                               │
                               ▼
            ┌──────────────────────────────────────┐
            │   Structured Model (dataclass)      │
            │   ConfigData / Interface / ...      │
            └─────────┬─────────────────┬──────────┘
                      │                 │
                      ▼                 ▼
        ┌──────────────────────┐   ┌──────────────────────┐
        │   Rule Engine        │   │   Secret Scanner     │
        │   R001..R079         │   │   (credential lines) │
        │   (parser tabanlı)   │   │   R062..R068         │
        └──────────┬───────────┘   └──────────┬───────────┘
                   │                          │
                   └─────────────┬────────────┘
                                 │
                                 ▼
            ┌──────────────────────────────────────┐
            │   Recommendation Layer               │
            │   (per-rule actionable advice)      │
            └──────────────────┬───────────────────┘
                               │
            ┌──────────────────┼───────────────────┐
            ▼                  ▼                   ▼
       ┌─────────┐       ┌─────────┐         ┌──────────┐
       │   CLI   │       │  Web UI │         │  Report  │
       │  (JSON) │       │ (Flask) │         │ (HTML/PDF)│
       └─────────┘       └─────────┘         └──────────┘
```

---

## Klasör Yapısı

```text
netconfig-ai/
├── app/
│   ├── __init__.py
│   ├── ai_commentary.py     # bulgu için öneri üretimi + maskeleme entegrasyonu
│   ├── models.py            # dataclass tabanlı veri modelleri
│   ├── parser.py            # Cisco IOS regex + state machine parser
│   ├── rules.py             # 79 kontrol kuralı + kategori map
│   ├── secret_scanner.py    # parola / key tespiti + maskeleme
│   ├── device_type_policy.py  # cihaz türü tahmini + kural kapsamı filtrelemesi
│   ├── service.py           # tek dosya & diff analiz orkestrasyonu
│   └── templates/
│       ├── index.html       # web arayüzü (dark mode, animasyon, filtre)
│       └── report.html      # HTML / PDF rapor şablonu
├── samples/
│   └── sample_ios.cfg       # test için örnek Cisco IOS config
├── cli.py                   # terminal istemcisi (text + JSON çıktı)
├── web.py                   # Flask web uygulaması
├── requirements.txt         # Flask, xhtml2pdf
├── .gitignore
└── README.md
```

---

## Kurulum

### Gereksinimler
- **Python 3.10+** (3.11 / 3.12 önerilir)
- `pip`
- (Opsiyonel) Git

### Windows (PowerShell)

```powershell
git clone https://github.com/furkanklc1/netconfig-project.git
cd netconfig-project

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### macOS / Linux

```bash
git clone https://github.com/furkanklc1/netconfig-project.git
cd netconfig-project

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

> **xhtml2pdf** kurulumu Windows'ta Visual Studio Build Tools gerektirebilir.  
> Sadece HTML rapor kullanacaksanız bu paket olmadan da uygulama tamamen çalışır; PDF endpoint'i 503 ile düzgünce düşer.

---

## Çalıştırma

### Web UI (Flask)

```powershell
.\.venv\Scripts\python.exe web.py
```

Tarayıcı: <http://127.0.0.1:5000>

Arayüzde:
- **Configuration Dosya Analizi** kartına `.txt` / `.cfg` yükle → "Analiz Et"
- **Configuration Diff Analizi** kartına eski + yeni dosyayı yükle → "Diff Analizi Yap"
- Sağ üstteki **☀️ / 🌙** kayar butonla dark mode geçişi
- Bulgu listesinde **kategori chip'leri** ile filtreleme
- **HTML Rapor** / **PDF Rapor** indirme butonları

### CLI

```bash
.\.venv\Scripts\python.exe cli.py samples/sample_ios.cfg
.\.venv\Scripts\python.exe cli.py samples/sample_ios.cfg --json
```

CLI çıktısı bulguların özetini, JSON modu ise programatik kullanım için tam yapılandırılmış nesneyi döner.

---

## Configuration Diff Analizi

İki config dosyasını yükleyerek **değişiklik etkisini** analiz edebilirsiniz.

Sistem size şunları sunar:

- **Değiştirilen satırlar** (eski → yeni eşleşmeli, masked)
- **Eklenenler** (parent + child gruplaması: ör. `vlan 30` ve `name IT` aynı kart)
- **Silinenler** (gruplanmış)
- **Yeni oluşan riskler** (severity rozetli, sıralı)
- **Çözülen riskler** (severity rozetli, sıralı)
- **Vendor / hostname / cihaz türü uyumsuzluk uyarıları** (yanlış dosyaları kıyaslama riskine karşı)

> Pratik kullanım: *"Son değişiklik ağı bozdu mu?"* sorusunu saniyeler içinde yanıtlar.

---

## Kural Seti

Toplam **79** kural, 5 kategoride:

### Security (35 kural)

`R002`, `R007`, `R008`, `R009`, `R010`, `R011`, `R012`, `R013`, `R014`, `R018`,
`R020`, `R021`, `R022`, `R027`, `R028`, `R031`, `R032`, `R040`, `R041`,
`R046`, `R047`, `R048`, `R049`, `R052`,
`R062`, `R063`, `R064`, `R065`, `R066`, `R067`, `R068` *(secret/credential scanning)*,
`R071`, `R072`, `R073`, `R078`

### Routing (13 kural)

`R005`, `R006`, `R050`, `R051`, `R053`, `R054`, `R055`, `R056`, `R057`, `R058`, `R059`, `R060`, `R061`

### L2 / Switching (10 kural)

`R025`, `R026`, `R029`, `R030`, `R033`, `R034`, `R035`, `R036`, `R037`, `R045`

### Compliance (2 kural)

`R017`, `R069`

### Operations (19 kural)

`R001`, `R003`, `R004`, `R015`, `R016`, `R019`, `R023`, `R024`, `R038`, `R039`, `R042`, `R043`,
`R044`, `R070`, `R074`, `R075`, `R076`, `R077`, `R079`

### Tüm Kuralların Listesi

| ID | Severity | Açıklama |
|---|---|---|
| R001 | medium | Tanımlı ama hiçbir interface'te kullanılmayan VLAN |
| R002 | high | ACL içinde aşırı geniş `permit ip any any` |
| R003 | medium | `shutdown` durumda olup `trunk` tanımlı interface |
| R004 | low | Interface üzerinde `description` eksik |
| R005 | medium | Interface OSPF area değeri ile process area beklentisi uyuşmuyor |
| R006 | high | BGP neighbor tanımlı ancak route-map uygulanmamış |
| R007 | high | SSH v1 açık |
| R008 | medium | Console portunda `exec-timeout` ayarlanmamış |
| R009 | high | SNMP varsayılan `public/private` community kullanımı |
| R010 | high | `enable secret` tanımı yok |
| R011 | medium | `service password-encryption` etkin değil |
| R012 | high | `line vty` altında Telnet erişimi açık |
| R013 | high | `ip http server` etkin (web management açık) |
| R014 | high | `aaa new-model` aktif değil |
| R015 | medium | Uzak syslog (`logging host`) tanımlı değil |
| R016 | medium | `ntp server` tanımlı değil |
| R017 | medium | `banner motd` tanımlı değil |
| R018 | high | `login block-for` tanımlı değil (brute-force) |
| R019 | low | `no ip domain-lookup` ayarlanmamış |
| R020 | medium | `service finger` / `ip finger` aktif |
| R021 | medium | `no ip source-route` ayarlanmamış |
| R022 | medium | `no service pad` ayarlanmamış |
| R023 | medium | `no cdp run` ayarlanmamış |
| R024 | medium | `clock timezone` tanımlı değil |
| R025 | medium | `spanning-tree portfast bpduguard default` etkin değil |
| R026 | medium | Trunk arayüzde native VLAN varsayılan/eksik |
| R027 | medium | VTY hatlarında `access-class` ACL'i tanımlı değil |
| R028 | high | `enable password` (zayıf) tanımlı |
| R029 | high | `ip dhcp snooping` aktif değil |
| R030 | medium | `ip arp inspection` tanımlı değil |
| R031 | medium | VTY için `exec-timeout` tanımlı değil |
| R032 | medium | `line aux` `no exec` ile devre dışı bırakılmamış |
| R033 | medium | `spanning-tree mode` tanımlı değil veya `pvst` (eski) |
| R034 | medium | Trunk'ta `switchport nonegotiate` yok (DTP açık) |
| R035 | medium | Access portu varsayılan VLAN 1'i kullanıyor |
| R036 | medium | Access portunda `port-security` tanımlı değil |
| R037 | medium | Access portunda `bpduguard enable` tanımlı değil |
| R038 | low | `service tcp-keepalives-in/out` etkin değil |
| R039 | low | `logging buffered` tanımlı değil |
| R040 | low | `ip ssh time-out` tanımlı değil |
| R041 | low | `ip ssh authentication-retries` tanımlı değil |
| R042 | low | `archive` (config archive) etkin değil |
| R043 | low | Loopback arayüzü tanımlı değil |
| R044 | low | Access portunda `no cdp enable` yok |
| R045 | low | Access portunda `storm-control` tanımlı değil |
| R046 | high | SNMP community kullanılıyor ama SNMPv3 user/group yok |
| R047 | high | SNMPv2c community ACL ile kısıtlanmamış |
| R048 | high | Control Plane Policing (CoPP) tanımlı değil |
| R049 | high | RSA anahtar uzunluğu 2048 bit'in altında |
| R050 | high | OSPF area için authentication tanımlı değil |
| R051 | high | BGP neighbor için MD5 password tanımlı değil |
| R052 | medium | L3 interface'inde uRPF (`ip verify unicast ... rx`) yok |
| R053 | medium | OSPF `passive-interface default` tanımlı değil |
| R054 | medium | OSPF `router-id` explicit tanımlı değil |
| R055 | low | OSPF `log-adjacency-changes` tanımlı değil |
| R056 | low | OSPF `auto-cost reference-bandwidth` tanımlı değil veya çok düşük |
| R057 | high | BGP neighbor için `maximum-prefix` tanımlı değil (eBGP'de kritik) |
| R058 | high | eBGP neighbor için `ttl-security hops` (GTSM) tanımlı değil |
| R059 | low | BGP `bgp log-neighbor-changes` tanımlı değil |
| R060 | low | BGP neighbor için `description` tanımlı değil |
| R061 | medium | iBGP neighbor için `update-source` tanımlı değil |
| R062 | critical | Cisco Type 7 password (kolay decode edilir) |
| R063 | critical | Type 0 (cleartext) password |
| R064 | critical | TACACS+ key cleartext olarak tanımlanmış |
| R065 | critical | RADIUS key cleartext olarak tanımlanmış |
| R066 | critical | BGP neighbor password cleartext |
| R067 | critical | OSPF MD5 / authentication-key cleartext |
| R068 | critical | ISAKMP/IPsec pre-shared key cleartext |
| R069 | medium | NTP sunucusu var; kimlik doğrulama anahtarı / `ntp authenticate` yok |
| R070 | medium | Syslog kullanılıyor; `logging source-interface` yok |
| R071 | high | TACACS+ var; `ip tacacs source-interface` yok |
| R072 | high | RADIUS var; `ip radius source-interface` yok |
| R073 | high | Yerel kullanıcı `username ... password` (secret değil) |
| R074 | low | Uzak syslog varken `service timestamps log datetime msec` yok |
| R075 | medium | `no ip cef` (CEF kapalı) |
| R076 | low | SNMP kullanılıyor; `snmp-server contact` yok |
| R077 | low | SNMP kullanılıyor; `snmp-server location` yok |
| R078 | medium | PKI trustpoint var; `ip domain-name` yok |
| R079 | medium | `archive` var; `log config` (config change log) yok |

---

## Yapay Zeka Entegrasyonu

Mevcut sürüm **regex tabanlı bir parser**, **kural motoru** ve **kural bazlı öneri katmanından** oluşur. Sonuçlar:

- **Deterministik** (aynı config → aynı bulgu)
- **Denetlenebilir** (her bulgu hangi kuraldan geliyor net görünür)
- **Hızlı** (büyük configler için bile <1 sn)

Proje, ilerleyen sürümlerde **LLM tabanlı bir akıllı yorumlayıcı katmanı** ile genişletilecektir.

Planlanan AI özellikleri:

- **Bağlama duyarlı öneriler** — sabit metin yerine config içeriğine özel, doğal dil önerileri
- **Otomatik özetleme** — yüzlerce satırlık config için yönetici özeti
- **Anomali tespiti** — geçmiş config havuzundan öğrenen ML tabanlı sapma analizi
- **Doğal dil sorgu** — *"Bu cihazda en kritik 3 risk nedir?"* gibi sorulara cevap

LLM katmanı eklendiğinde mevcut kural motoru çalışmaya devam edecek; AI yalnızca **yorum / zenginleştirme** görevini üstlenecektir.

---

## Yol Haritası

- [ ] **AI / LLM entegrasyonu** (bağlama duyarlı öneri, doğal dil sorgu, anomali tespiti)
- [ ] Juniper / HP / Arista parser desteği
- [ ] Harici rule tanımı (YAML / JSON tabanlı dinamik rule engine)
- [ ] Multi-config batch analiz
- [ ] CSV rapor çıktısı
- [ ] Rule coverage için otomatik test seti
- [ ] Trend grafiği ve zaman serisi analizi
- [x] PDF / HTML rapor çıktısı
- [x] Light / Dark mode
- [x] Secret / Credential Scanner
- [x] Vendor / Platform fingerprinting
- [x] Configuration Diff Analysis

---

## Katkı

Pull request ve önerilere açıktır.

Yeni kural fikirleri için aşağıdakileri paylaşmanız yeterlidir:

- Kural adı ve amacı
- Tespit mantığı (regex / state)
- Örnek config satırları
- Beklenen öneri metni
- Kategorisi (`security` / `routing` / `l2` / `compliance` / `operations`)
- Severity tahmini (`critical` / `high` / `medium` / `low`)

---

## İletişim

<div align="left">

**Furkan KILIÇ**  
[furkanklc03@gmail.com](mailto:furkanklc03@gmail.com)

</div>

---

> Bu proje eğitim ve prototip amaçlıdır; üretim ortamında kullanmadan önce kendi gereksinimlerinize göre uyarlayabilirsiniz.
