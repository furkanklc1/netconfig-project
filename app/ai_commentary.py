from app.models import Finding


def enrich_finding(finding: Finding) -> str:
    if finding.rule_id == "R001":
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
            "maskelereyin. Mümkünse modern kimlik doğrulama yöntemlerini tercih edin."
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
            "`no ip domain-lookup` ekleyerek hatalı komutların DNS sorgusu yapmasını "
            "engelleyin."
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
            "Yönetim segmenti dışında CDP'yi kapatın (`no cdp run`) veya en azından "
            "edge interface'lerde `no cdp enable` uygulayın."
        )
    if finding.rule_id == "R024":
        return (
            "`clock timezone` ve gerekirse `clock summer-time` ile saat dilimi tanımlayın."
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
    return "Konfigürasyonu iş gereksinimine göre gözden geçirin."


def format_report(findings: list[Finding]) -> list[dict]:
    return [
        {
            "rule_id": item.rule_id,
            "severity": item.severity,
            "message": item.message,
            "context": item.context,
            "category": item.category,
            "recommendation": enrich_finding(item),
        }
        for item in findings
    ]
