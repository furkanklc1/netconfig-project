import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.service import audit_bundle


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetConfig AI - Cisco IOS config denetleyici"
    )
    parser.add_argument("config_path", help="Analiz edilecek .cfg/.txt dosya yolu")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Çıktıyı JSON formatında yazdır",
    )
    args = parser.parse_args()

    config_path = Path(args.config_path)
    try:
        config_text = config_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        config_text = config_path.read_text(encoding="latin-1")
    report, device_info = audit_bundle(config_text)

    if args.json:
        print(json.dumps({"device_info": device_info, "report": report}, ensure_ascii=False, indent=2))
        return

    if not report:
        print("Riskli bir yapılandırma bulunamadı.")
        return

    print(
        f"Cihaz türü: {device_info.get('device_type_label', '-')} "
        f"({device_info.get('device_type_note', '')})"
    )
    print(f"Toplam bulgu: {len(report)}")
    print("-" * 60)
    for idx, item in enumerate(report, start=1):
        print(f"{idx}) [{item['severity'].upper()}] {item['message']}")
        print(f"   Rule: {item['rule_id']}")
        if item.get("occurrence_count", 1) > 1:
            print(f"   Tekilleştirilmiş konum sayısı: {item['occurrence_count']}")
        print(f"   Context: {item['context']}")
        print(f"   Öneri: {item['recommendation']}")
        print()


if __name__ == "__main__":
    main()
