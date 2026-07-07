# core/utils.py
import sys
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("osint.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("OSINT")

# Оригинальный stdout для дублирования
ORIGINAL_STDOUT = sys.__stdout__


def dual_print(*args, **kwargs):
    """Печатает одновременно в консоль и в оригинальный stdout."""
    print(*args, **kwargs)
    if ORIGINAL_STDOUT:
        print(*args, file=ORIGINAL_STDOUT, **kwargs)


def print_section(title):
    dual_print(f"\n{'─' * 58}")
    dual_print(f"  ▸ {title}")
    dual_print(f"{'─' * 58}")


def print_field(label, value, indent=4):
    """Выводит поле, если значение непустое."""
    if value is None:
        return
    v = str(value).strip()
    if v and v.lower() not in ("none", "null", "n/a", "false"):
        dual_print(f"{' ' * indent}{label:<26} {v}")


def print_summary(items: dict, title: str):
    """Итоговая таблица."""
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  ✔ ИТОГ: {title}  ({len(items)} найдено)")
    dual_print(f"{'═' * 58}")
    if items:
        for k, v in sorted(items.items()):
            dual_print(f"    • {k:<22} {v}")
    else:
        dual_print("  Ничего не найдено.")
    dual_print(f"{'═' * 58}")
