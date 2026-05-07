import argparse
import json
from pathlib import Path

from app.service import audit_config_text


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
    config_text = config_path.read_text(encoding="utf-8")
    report = audit_config_text(config_text)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    if not report:
        print("Riskli bir yapılandırma bulunamadı.")
        return

    print(f"Toplam bulgu: {len(report)}")
    print("-" * 60)
    for idx, item in enumerate(report, start=1):
        print(f"{idx}) [{item['severity'].upper()}] {item['message']}")
        print(f"   Rule: {item['rule_id']}")
        print(f"   Context: {item['context']}")
        print(f"   Öneri: {item['recommendation']}")
        print()


if __name__ == "__main__":
    main()
