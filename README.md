# NetConfig AI

Cisco IOS konfigürasyon dosyalarını analiz eden, **akıllı** bir network config auditor.  
`.txt` / `.cfg` dosyalarını okur, 61 farklı güvenlik / operasyon / uyumluluk kontrolü çalıştırır ve her bulgu için aksiyon odaklı öneri üretir.

> **Not:** Bu sürüm yalnızca **Cisco IOS / IOS XE** konfigürasyonlarını analiz eder. NX-OS, Arista EOS, Juniper Junos ve diğer vendor'lar için destek yol haritasındadır.

> Bu proje aktif geliştirme aşamasındadır ve sürekli güncellenmektedir.

## Proje Şu An Nasıl Çalışıyor?

NetConfig AI'nın mevcut sürümü, **regex tabanlı bir parser**, **kural motoru** ve **kural bazlı öneri katmanından** oluşur:

- **Parser** Cisco IOS söz dizimini state machine + regex ile yapısal modele çevirir.
- **Rule Engine** 61 ayrı kontrolü çalıştırarak güvenlik/operasyon bulguları üretir.
- **Recommendation Layer** her bulgu için aksiyon odaklı, sektör best-practice referanslı öneri üretir.

Bu mimari sayesinde:

- Sonuçlar **deterministik** (aynı config → aynı bulgu) ve **denetlenebilir**dir.
- Kural ekleme / değiştirme **dakikalar** içinde yapılabilir.
- Üretim ortamı için **güvenli ve hızlı** bir analiz sağlar.

## Yapay Zeka Entegrasyonu

Proje, ilerleyen sürümlerde **LLM tabanlı bir akıllı yorumlayıcı katmanı** ile genişletilecektir. 

Planlanan AI özellikleri:

- **Bağlama duyarlı öneriler**: Sabit metin yerine config içeriğine özel, doğal dil önerileri
- **Otomatik özetleme**: Yüzlerce satırlık config için yönetici özeti
- **Anomali tespiti**: Geçmiş config havuzundan öğrenen ML tabanlı sapma analizi
- **Doğal dil sorgu**: "Bu cihazda en kritik 3 risk nedir?" gibi sorulara cevap

LLM katmanı eklendiğinde mevcut kural motoru çalışmaya devam edecek; AI yalnızca **yorum / zenginleştirme** görevini üstlenecektir.

---

## İçindekiler

- [Özellikler](#özellikler)
- [Mimari](#mimari)
- [Klasör Yapısı](#klasör-yapısı)
- [Kurulum](#kurulum)
- [Çalıştırma](#çalıştırma)
- [Configuration Diff Analizi](#configuration-diff-analizi)
- [Kural Seti](#kural-seti)
- [Yol Haritası](#yol-haritası)
- [Katkı](#katkı)
- [İletişim](#i̇letişim)

---

## Özellikler

- **Cisco IOS** odaklı konfigürasyon parse desteği
- 61 hazır kural (`R001..R061`)
- 5 kategori: `security`, `routing`, `l2`, `compliance`, `operations`
- 3 severity seviyesi: `low`, `medium`, `high`
- Her bulgu için **aksiyon odaklı öneri metni**
- **Web arayüzü** (Flask + Bootstrap, modern UI)
- **CLI** desteği (terminal üzerinden analiz, JSON çıktı)
- **Configuration Diff Analizi**: iki config dosyasını karşılaştırır
  - Değiştirilen satırlar (Eski → Yeni)
  - Eklenen satırlar (gruplanmış)
  - Silinen satırlar (gruplanmış)
  - Yeni oluşan riskler / çözülen riskler
- **Kategori filtreleme** (Security / Routing / L2 / Compliance / Operations)

---

## Mimari

```text
Config File (.txt / .cfg)
        |
        v
Parser (regex + state machine)
        |
        v
Structured Model (dataclass)
        |
        v
Rule Engine (R001..R061)
        |
        v
Recommendation Layer
        |
        +--> CLI output (text / JSON)
        +--> Web UI (Flask)
```

---

## Klasör Yapısı

```text
netconfig-ai/
├── app/
│   ├── ai_commentary.py     # bulgu için öneri üretimi
│   ├── models.py            # dataclass tabanlı veri modelleri
│   ├── parser.py            # Cisco IOS regex parser
│   ├── rules.py             # 45 kontrol kuralı + kategori map
│   ├── service.py           # tek dosya & diff analiz orkestrasyonu
│   └── templates/
│       └── index.html       # web arayüzü
├── samples/
│   └── sample_ios.cfg
├── cli.py                   # terminal istemcisi
├── web.py                   # Flask web arayüzü
├── requirements.txt
└── README.md
```

---

## Kurulum

### Gereksinimler

- Python **3.10+** (3.11 / 3.12 önerilir)
- pip
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

---

## Çalıştırma

### Web UI (Flask)

```powershell
.\.venv\Scripts\python.exe web.py
```

Tarayıcı: [http://127.0.0.1:5000](http://127.0.0.1:5000)

### CLI

```powershell
.\.venv\Scripts\python.exe cli.py samples/sample_ios.cfg
.\.venv\Scripts\python.exe cli.py samples/sample_ios.cfg --json
```

---

## Configuration Diff Analizi

İki config dosyasını yükleyerek **değişiklik etkisini** analiz edebilirsiniz.

Sistem size:

- **Değiştirilen satırlar** (eski → yeni eşleşmeli)
- **Eklenenler** (parent + child gruplaması: ör. `vlan 30` ve `name IT` aynı kart)
- **Silinenler** (gruplanmış)
- **Yeni oluşan riskler** (severity rozetli)
- **Çözülen riskler**

panelleri olarak sunar.

> Pratik kullanım: "Son değişiklik ağı bozdu mu?" sorusunu hızlıca yanıtlar.

---

## Kural Seti

Toplam **61** kural, 5 kategoride:

### Security

`R002`, `R007`, `R008`, `R009`, `R010`, `R011`, `R012`, `R013`, `R014`, `R018`,
`R020`, `R021`, `R022`, `R023`, `R027`, `R028`, `R031`, `R032`, `R040`, `R041`, `R044`,
`R046`, `R047`, `R048`, `R049`, `R052`

### Routing

`R005`, `R006`, `R050`, `R051`, `R053`, `R054`, `R055`, `R056`, `R057`, `R058`, `R059`, `R060`, `R061`

### L2 / Switching

`R025`, `R026`, `R029`, `R030`, `R033`, `R034`, `R035`, `R036`, `R037`, `R045`

### Compliance

`R017`

### Operations

`R001`, `R003`, `R004`, `R015`, `R016`, `R019`, `R024`, `R038`, `R039`, `R042`, `R043`

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

---

## Yol Haritası

- [ ] **AI / LLM entegrasyonu** (bağlama duyarlı öneri, doğal dil sorgu, anomali tespiti)
- [ ] Juniper / HP / Arista parser desteği
- [ ] Harici rule tanımı (YAML / JSON tabanlı dinamik rule engine)
- [ ] PDF / CSV rapor çıktısı
- [ ] Rule coverage için otomatik test seti
- [ ] Multi-config batch analiz
- [ ] Skor (compliance score) ve trend grafiği
- [ ] Dark mode

---

## Katkı

Pull request ve önerilere açıktır.

Yeni kural fikirleri için aşağıdakileri paylaşmanız yeterlidir:

- Kural adı ve amacı
- Tespit mantığı (regex / state)
- Örnek config satırları
- Beklenen öneri metni

---

## İletişim

**Furkan KILIÇ**  
[furkanklc03@gmail.com](mailto:furkanklc03@gmail.com)

---

> Bu proje eğitim ve prototip amaçlıdır; üretim ortamında kullanmadan önce kendi gereksinimlerinize göre uyarlayabilirsiniz.
