from app.models import Finding
from app.rules import RULE_CATEGORIES
from app.secret_scanner import mask_credentials_in_line


def enrich_finding(finding: Finding) -> str:
    if finding.rule_id == "R001":
        if getattr(finding, "occurrence_count", 1) > 1:
            return (
                "Kullanılmayan VLAN'ları kaldırın veya ilgili access/trunk arayüzlerine "
                "atayın; isimlendirme ve VLAN matrisi dokümantasyonunu güncel tutun."
            )
        return (
            "Bu VLAN artık kullanılmıyorsa kaldırın; kullanılacaksa ilgili access/trunk "
            "arayüzüne atayın."
        )
    if finding.rule_id == "R002":
        return (
            "Kuralı kaynak/hedef ağ ve port bazında daraltın. Zero-trust yaklaşımı için "
            "minimum yetki prensibini uygulayın."
        )
    if finding.rule_id == "R003":
        return (
            "Bu port geçici olarak kapalıysa change kaydı ekleyin; değilse portu açın veya "
            "trunk tanımını kaldırın."
        )
    if finding.rule_id == "R004":
        return (
            "Arayüzün amacını açıklayan kısa bir description ekleyin. Bu, operasyon ve "
            "incident süreçlerinde hızlı analiz sağlar."
        )
    if finding.rule_id == "R005":
        return (
            "OSPF process ve interface area değerlerini standart tasarıma göre hizalayın. "
            "Area uyuşmazlıkları komşuluk kurulmasını bozabilir."
        )
    if finding.rule_id == "R006":
        return (
            "BGP neighbor için en azından inbound veya outbound route-map uygulayın. "
            "Politikasız peering istenmeyen route kabul/ilan riskini artırır."
        )
    if finding.rule_id == "R007":
        return (
            "SSH sürümünü 2'ye yükseltin ve sadece güçlü şifre kümeleri bırakın. "
            "SSH v1 modern güvenlik gereksinimlerini karşılamaz."
        )
    if finding.rule_id == "R008":
        return (
            "Console line altında `exec-timeout` tanımlayın (ör. 5 0). Bu, açık kalan "
            "oturumların kötüye kullanım riskini azaltır."
        )
    if finding.rule_id == "R009":
        return (
            "Varsayılan SNMP community stringlerini kaldırın, rastgele güçlü değerler "
            "kullanın veya mümkünse SNMPv3'e geçin."
        )
    if finding.rule_id == "R010":
        return (
            "Cihazda `enable secret` tanımlayın ve eski `enable password` kullanımını "
            "kaldırın. Ayrıcalıklı mod erişimini güçlü hash ile koruyun."
        )
    if finding.rule_id == "R011":
        return (
            "`service password-encryption` etkinleştirerek düz metin görünen parolaları "
            "maskeleyin. Mümkünse modern kimlik doğrulama yöntemlerini tercih edin."
        )
    if finding.rule_id == "R012":
        return (
            "VTY erişiminde Telnet'i kapatıp yalnızca SSH kullanın (`transport input ssh`). "
            "Telnet şifreleme sağlamadığı için CIS ile uyumsuzdur."
        )
    if finding.rule_id == "R013":
        return (
            "Web yönetimini kapatın (`no ip http server`). Gerekirse sadece `ip http "
            "secure-server` kullanın ve ACL ile sınırlandırın."
        )
    if finding.rule_id == "R014":
        return (
            "`aaa new-model` etkinleştirip TACACS+/RADIUS ile merkezi kimlik doğrulama "
            "ve yetkilendirme tanımlayın."
        )
    if finding.rule_id == "R015":
        return (
            "Cihaz loglarını merkezi syslog sunucusuna gönderin (`logging host <ip>`). "
            "Bu, olay müdahalesi için kritiktir."
        )
    if finding.rule_id == "R016":
        return (
            "`ntp server <ip>` ile zaman senkronizasyonu sağlayın. Doğru zaman damgası "
            "log korelasyonu ve adli analiz için zorunludur."
        )
    if finding.rule_id == "R017":
        return (
            "`banner motd` ile yetkisiz erişimi engelleyen yasal bir uyarı metni "
            "tanımlayın."
        )
    if finding.rule_id == "R018":
        return (
            "`login block-for ... attempts ... within ...` tanımlayarak başarısız giriş "
            "denemelerine karşı brute-force koruması ekleyin."
        )
    if finding.rule_id == "R019":
        return (
            "Operasyonel iyi uygulama: `no ip domain-lookup` ekleyerek hatalı komutların "
            "DNS sorgusu yapmasını engelleyin (doğrudan bir güvenlik açığı değildir)."
        )
    if finding.rule_id == "R020":
        return (
            "Finger servisini kapatın (`no service finger` veya `no ip finger`). Açık "
            "olması kullanıcı bilgisi sızdırabilir."
        )
    if finding.rule_id == "R021":
        return (
            "`no ip source-route` ile IP source routing'i kapatın. Saldırganın trafik "
            "yönlendirmesini engeller."
        )
    if finding.rule_id == "R022":
        return (
            "`no service pad` ile X.25 PAD servisini kapatın. Modern ortamda gereksizdir."
        )
    if finding.rule_id == "R023":
        return (
            "Operasyonel öneri: CDP'yi kapatın (`no cdp run`) veya yalnızca yönetim "
            "segmentinde bırakın; edge'de `no cdp enable` uygulayın. Bilgi sızdırma "
            "riski düşüktür ve yönlendirme kimlik doğrulamasıyla aynı öncelikte değildir."
        )
    if finding.rule_id == "R024":
        return (
            "Log ve olay korelasyonu için `clock timezone` ve gerekirse `clock summer-time` "
            "ile saat dilimi tanımlayın (işletim/denetim önerisi)."
        )
    if finding.rule_id == "R025":
        return (
            "Tüm access portları için `spanning-tree portfast bpduguard default` "
            "etkinleştirin. Yetkisiz switch bağlantılarına karşı koruma sağlar."
        )
    if finding.rule_id == "R026":
        return (
            "Trunk native VLAN'ını kullanıcı VLAN'larından farklı, özel ve kullanılmayan "
            "bir VLAN'a alın. VLAN hopping saldırılarına karşı koruma sağlar."
        )
    if finding.rule_id == "R027":
        return (
            "VTY hatlarında yönetim ağına özel `access-class` ACL'i uygulayın. "
            "Uzaktan yönetim arayüzünü internete açık bırakmayın."
        )
    if finding.rule_id == "R028":
        return (
            "`enable password` yerine `enable secret` kullanın. `enable password` "
            "geri çevrilebilir Type 7 hash kullanır."
        )
    if finding.rule_id == "R029":
        return (
            "Erişim katmanı switchlerinde `ip dhcp snooping` etkinleştirin ve trust "
            "portları DHCP server tarafına yönlendirin."
        )
    if finding.rule_id == "R030":
        return (
            "Dynamic ARP Inspection (`ip arp inspection vlan`) etkinleştirin ve "
            "DHCP snooping ile birlikte ARP poisoning saldırılarını engelleyin."
        )
    if finding.rule_id == "R031":
        return (
            "VTY hatlarına `exec-timeout` (ör. 10 0) tanımlayın. Boşta kalan oturumlar "
            "saldırganlar tarafından devralınabilir."
        )
    if finding.rule_id == "R032":
        return (
            "AUX hattını kapatın (`no exec`). Kullanılmayan modem/console portlarına "
            "erişim güvenlik riski oluşturur."
        )
    if finding.rule_id == "R033":
        return (
            "`spanning-tree mode rapid-pvst` veya `mst` kullanın. Klasik PVST yakınsama "
            "süresi modern ağlarda yetersizdir."
        )
    if finding.rule_id == "R034":
        return (
            "Trunk portlarda `switchport nonegotiate` ekleyerek DTP'yi kapatın. "
            "Pasif DTP açıkları VLAN hopping saldırılarına yol açar."
        )
    if finding.rule_id == "R035":
        return (
            "Access portları VLAN 1 (default) yerine kullanıcı için tanımlanmış "
            "ayrı bir VLAN'a alın. VLAN 1'i yönetim için de kullanmayın."
        )
    if finding.rule_id == "R036":
        return (
            "Access portlarda `switchport port-security` ile maksimum MAC adresi "
            "ve violation politikası tanımlayın."
        )
    if finding.rule_id == "R037":
        return (
            "Access portlarda `spanning-tree bpduguard enable` veya global "
            "`spanning-tree portfast bpduguard default` uygulayın."
        )
    if finding.rule_id == "R038":
        return (
            "Operasyonel öneri: `service tcp-keepalives-in` ve `service tcp-keepalives-out` "
            "ile yarım açık TCP oturumlarının kaynak tüketmesini azaltın (güvenlik "
            "bulgusu değildir)."
        )
    if finding.rule_id == "R039":
        return (
            "`logging buffered <size> informational` ile yerel log buffer'ını "
            "etkinleştirin. Bu, syslog erişilemediğinde olay analizi için kritiktir."
        )
    if finding.rule_id == "R040":
        return (
            "`ip ssh time-out 60` (ya da kuruma uygun değer) ekleyerek tamamlanmamış "
            "SSH oturumları için zaman aşımı tanımlayın."
        )
    if finding.rule_id == "R041":
        return (
            "`ip ssh authentication-retries 3` ekleyerek SSH brute-force denemelerini "
            "sınırlandırın."
        )
    if finding.rule_id == "R042":
        return (
            "Operasyonel/denetim: `archive` modunu etkinleştirip `log config` ile "
            "konfigürasyon değişikliklerini izleyin; audit ve geri alma süreçleri kolaylaşır."
        )
    if finding.rule_id == "R043":
        return (
            "Routing protokollerinin stabil çalışması için en az bir Loopback "
            "interface tanımlayın (yönetim ve router-id için)."
        )
    if finding.rule_id == "R044":
        return (
            "Operasyonel öneri: kullanıcı portlarında CDP'yi kapatın (`no cdp enable`). "
            "Komşu cihaz bilgisi sızıntısını azaltır; tipik bir güvenlik zafiyeti "
            "sınıflandırması değildir."
        )
    if finding.rule_id == "R045":
        return (
            "Access portlarda `storm-control broadcast/multicast level <eşik>` "
            "tanımlayarak broadcast storm risklerini sınırlayın."
        )
    if finding.rule_id == "R046":
        return (
            "SNMPv3 yapılandırması ekleyin: `snmp-server group ... v3 priv` ve "
            "`snmp-server user ... v3 auth sha ... priv aes 128 ...`. Plaintext "
            "v1/v2c community kullanımını sonlandırın."
        )
    if finding.rule_id == "R047":
        return (
            "SNMPv2c kullanılacaksa community string'i ACL ile kısıtlayın "
            "(`snmp-server community <name> RO <ACL>`). ACL yalnızca yönetim "
            "ağındaki NMS sunucularına izin vermeli."
        )
    if finding.rule_id == "R048":
        return (
            "Control Plane Policing tanımlayın: management/routing trafiği için "
            "`class-map`/`policy-map` oluşturup `control-plane` altında "
            "`service-policy input <map>` uygulayın. CPU'yu DoS'tan korur."
        )
    if finding.rule_id == "R049":
        return (
            "RSA anahtarını yenileyin: `crypto key zeroize rsa` ardından "
            "`crypto key generate rsa modulus 2048` (kurum politikasına göre 4096)."
        )
    if finding.rule_id == "R050":
        return (
            "Öncelikli güvenlik: OSPF area için `area <id> authentication message-digest` "
            "ve komşu interface'lerde `ip ospf message-digest-key <id> md5 <güçlü-key>` "
            "tanımlayın. Kimlik doğrulanmamış OSPF komşuluğu, sahte LSA ve yönlendirme "
            "manipülasyonuna yol açabilir."
        )
    if finding.rule_id == "R051":
        return (
            "BGP neighbor'a MD5 password ekleyin: `neighbor <ip> password <key>`. "
            "Mümkünse TCP-AO veya bağlantı için IPsec tercih edin."
        )
    if finding.rule_id == "R052":
        return (
            "WAN/edge L3 interface'lerinde uRPF etkinleştirin: "
            "`ip verify unicast source reachable-via rx`. Asimetrik routing varsa "
            "`reachable-via any` kullanılabilir."
        )
    if finding.rule_id == "R053":
        return (
            "OSPF process altında `passive-interface default` tanımlayın ve sadece "
            "komşu kurulması gereken interface'leri `no passive-interface <intf>` ile "
            "açın. Bu, kullanıcı VLAN'larına LSA sızmasını engeller."
        )
    if finding.rule_id == "R054":
        return (
            "OSPF process altında `router-id A.B.C.D` ile sabit Router-ID tanımlayın "
            "(genelde Loopback IP'si). Aksi halde IP değişimleri komşulukları sıfırlar."
        )
    if finding.rule_id == "R055":
        return (
            "OSPF process altında `log-adjacency-changes detail` ekleyerek komşu state "
            "geçişlerini syslog'a düşürün."
        )
    if finding.rule_id == "R056":
        return (
            "OSPF process altında `auto-cost reference-bandwidth 100000` (10G referans) "
            "veya kuruma uygun bir değer tanımlayın. Aksi halde 1G+ linkler aynı maliyete "
            "düşer ve path selection bozulur."
        )
    if finding.rule_id == "R057":
        return (
            "BGP neighbor için `neighbor <ip> maximum-prefix <N> [warning-only|restart]` "
            "tanımlayın. eBGP peer'ları için bu zorunlu sayılmalıdır; route-leak / DoS "
            "durumlarında peering'i otomatik koruma altına alır."
        )
    if finding.rule_id == "R058":
        return (
            "eBGP neighbor için `neighbor <ip> ttl-security hops <N>` (Generalized TTL "
            "Security Mechanism) tanımlayın. Sadece doğrudan komşunun TTL'si kabul edilir, "
            "uzak hop'tan gelen spoof TCP segmentleri filtrelenir."
        )
    if finding.rule_id == "R059":
        return (
            "BGP process altında `bgp log-neighbor-changes` ekleyerek peer up/down "
            "olaylarını syslog'a düşürün. Outage analizi için gerekli."
        )
    if finding.rule_id == "R060":
        return (
            "Her BGP neighbor'a `neighbor <ip> description <peer-name>` ekleyin. "
            "Operasyon ekibinin peer'ları hızlı tanımlamasını sağlar."
        )
    if finding.rule_id == "R061":
        return (
            "iBGP peering'lerinde `neighbor <ip> update-source Loopback0` kullanın. "
            "Aksi halde tek bir transit link arızası iBGP oturumunu düşürür."
        )
    if finding.rule_id == "R062":
        return (
            "Cisco Type 7 password reversible'dır ve internetteki araçlarla saniyeler "
            "içinde decode edilir. `service password-encryption` Type 7 üretir; gerçek "
            "koruma için `enable algorithm-type scrypt secret <pw>` ile Type 8/9 hash "
            "veya merkezi AAA kullanın."
        )
    if finding.rule_id == "R063":
        return (
            "Type 0 (cleartext) password kabul edilemez. `enable secret <pw>` veya "
            "`username X secret <pw>` ile Type 5/8/9 hash kullanın. Mevcut satırı "
            "konfigürasyon vault'una taşıyın."
        )
    if finding.rule_id == "R064":
        return (
            "TACACS+ key'i kalıcı olarak korumak için `key config-key password-encrypt` "
            "ile master key tanımlayıp `tacacs-server key 7 <enc>` kullanın. Tercihen "
            "secret'i Ansible Vault / HashiCorp Vault gibi bir kaynaktan deploy edin."
        )
    if finding.rule_id == "R065":
        return (
            "RADIUS key'i Type 7 encrypt edip cihazda master key tanımlayın. Daha güçlü "
            "koruma için RadSec (RADIUS over TLS) ile karşılıklı sertifika doğrulamasına "
            "geçin."
        )
    if finding.rule_id == "R066":
        return (
            "BGP neighbor password'ünü `neighbor <ip> password 7 <enc>` ile encrypt edin "
            "ve mümkünse TCP Authentication Option (TCP-AO) kullanın. Cleartext password "
            "show running-config çıktısında okunur."
        )
    if finding.rule_id == "R067":
        return (
            "OSPF MD5 anahtarını `service password-encryption` etkinken `ip ospf "
            "message-digest-key 1 md5 7 <enc>` formatında saklayın veya keychain "
            "kullanarak rotasyonu kolaylaştırın. Mümkünse HMAC-SHA-256 (Cisco IOS XE) "
            "destekleniyorsa onu tercih edin."
        )
    if finding.rule_id == "R068":
        return (
            "IPsec/ISAKMP pre-shared key'i `crypto isakmp key 6 <enc> address <peer>` "
            "ile Type 6 (AES) encrypt edin ve `password encryption aes` ile master key "
            "tanımlayın. Production için PSK yerine sertifika tabanlı IKE'ye geçin."
        )
    if finding.rule_id == "R069":
        return (
            "`ntp authenticate` ve `ntp authentication-key <id> md5 <key>` veya "
            "`ntp trusted-key <id>` tanımlayın; mümkünse `ntp server <ip> key <id>` "
            "ile sunucu bazlı anahtar kullanın. NTP spoofing ve saat kayması riskini azaltır."
        )
    if finding.rule_id == "R070":
        return (
            "Stabil bir loopback veya yönetim SVI üzerinden `logging source-interface "
            "<intf>` tanımlayın. Syslog sunucusu ACL'lerinde kaynak IP'yi sabitlemek için "
            "gerekir."
        )
    if finding.rule_id == "R071":
        return (
            "`ip tacacs source-interface <Loopback0|mgmt-SVI>` ekleyin. TACACS "
            "istemci IP'si tutarlı olmalı; aksi halde sunucu tarafı policy ve "
            "accounting kayıtları tutarsızlaşır."
        )
    if finding.rule_id == "R072":
        return (
            "`ip radius source-interface <Loopback0|mgmt-SVI>` ekleyin. RADIUS "
            "Accounting/CoA için kaynak IP'nin öngörülebilir olması gerekir."
        )
    if finding.rule_id == "R073":
        return (
            "`username <ad> secret <hash>` veya `algorithm-type scrypt` ile güçlü "
            "hash kullanın. `password` yerine `secret` tercih edin; mümkünse yerel "
            "kullanıcıyı kaldırıp yalnızca TACACS+/RADIUS ile oturum açtırın."
        )
    if finding.rule_id == "R074":
        return (
            "`service timestamps log datetime msec localtime` (ve gerekiyorsa "
            "`show-timezone`) ekleyin. SIEM ve korelasyon için milisaniye damgası "
            "standarttır."
        )
    if finding.rule_id == "R075":
        return (
            "Üretimde `no ip cef` kullanmayın; `ip cef` veya varsayılan CEF-on durumuna "
            "dönün. Sorun giderme için geçici kapatıldıysa change kaydı ve geri alma "
            "planı ekleyin."
        )
    if finding.rule_id == "R076":
        return (
            "`snmp-server contact <\"Ad Soyad / e-posta / telefon\">` tanımlayın. "
            "SNMP üzerinden envanter toplayan ekiplerin acil durumda ulaşacağı bilgi "
            "olmalıdır."
        )
    if finding.rule_id == "R077":
        return (
            "`snmp-server location <\"Bina / Kat / Kabinet\">` ile fiziksel konum "
            "belirtin. Kurumsal envanter ve saha müdahalesi için önerilir."
        )
    if finding.rule_id == "R078":
        return (
            "`ip domain-name <sirket.example.com>` tanımlayın. PKI enrollment, "
            "SCEP/EST ve sertifika CN/SAN doğrulaması için FQDN gereklidir."
        )
    if finding.rule_id == "R079":
        return (
            "Operasyonel/denetim: `archive` modülü altına `log config` ve `logging enable` "
            "ekleyin; path/maximum ayarlarınızı koruyarak değişiklikleri izlenebilir yapın "
            "(güvenlik bulgusu değildir)."
        )
    return "Konfigürasyonu iş gereksinimine göre gözden geçirin."


def format_report(findings: list[Finding]) -> list[dict]:
    return [
        {
            "rule_id": item.rule_id,
            "severity": item.severity,
            "message": item.message,
            "context": mask_credentials_in_line(item.context),
            "category": RULE_CATEGORIES.get(item.rule_id, item.category),
            "recommendation": enrich_finding(item),
            "occurrence_count": getattr(item, "occurrence_count", 1),
            "stable_key": getattr(item, "stable_key", None),
        }
        for item in findings
    ]
