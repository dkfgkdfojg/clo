# analyzers/face.py
"""Реверс по фото/лицу.

Для картинки по URL — сразу строит ссылки реверс-поиска (Yandex/Google Lens/
Bing/TinEye). Для локального файла — даёт порталы для ручной загрузки.
Плюс список специализированных face-поисковиков.

Этика: применять только к себе или в рамках законного расследования. Поиск по
лицу третьих лиц во многих юрисдикциях ограничен законом о перс. данных.
"""

from __future__ import annotations

from urllib.parse import quote

from core.utils import dual_print, print_section, print_field, print_summary

# Реверс по URL картинки.
REVERSE_BY_URL = {
    "Yandex Images": "https://yandex.com/images/search?rpt=imageview&url={}",
    "Google Lens": "https://lens.google.com/uploadbyurl?url={}",
    "Bing Visual": "https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{}",
    "TinEye": "https://tineye.com/search?url={}",
}

# Порталы для ручной загрузки файла.
UPLOAD_PORTALS = {
    "Google Lens": "https://lens.google.com/",
    "Yandex Images": "https://yandex.com/images/",
    "TinEye": "https://tineye.com/",
    "PimEyes (лицо)": "https://pimeyes.com/en",
    "FaceCheck.id (лицо)": "https://facecheck.id/",
    "Search4faces (VK/OK)": "https://search4faces.com/",
    "Betaface": "https://www.betaface.com/demo_old.html",
}


def analyze_face(target: str) -> None:
    t = target.strip()
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] РЕВЕРС ПО ФОТО: {t}")
    dual_print(f"{'═' * 58}")
    dual_print("  [!] Этика: только для себя или законного расследования.")

    results: dict[str, str] = {}
    is_url = t.lower().startswith(("http://", "https://"))

    if is_url:
        print_section("Реверс-поиск по ссылке на изображение")
        enc = quote(t, safe="")
        for name, tpl in REVERSE_BY_URL.items():
            url = tpl.format(enc)
            print_field(name, url)
            results[name] = url
    else:
        print_section("Локальный файл — загрузите вручную")
        dual_print("  Прямой реверс по локальному файлу требует загрузки на портал.")

    print_section("Порталы (в т.ч. поиск по лицу)")
    for name, url in UPLOAD_PORTALS.items():
        print_field(name, url)

    print_summary(results, f"Реверс {t[:24]}")


if __name__ == "__main__":
    import sys
    analyze_face(sys.argv[1] if len(sys.argv) > 1 else "https://example.com/photo.jpg")
