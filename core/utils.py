# core/utils.py
import sys
import threading
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

# Пока флаг взведён (внутри print_section/field/summary), вложенные вызовы
# dual_print не пишутся в отчёт повторно как «заметки».
_guard = threading.local()


def _report():
    """Ленивый импорт, чтобы избежать цикла utils<->report на старте пакета."""
    from core import report
    return report.current()


def dual_print(*args, **kwargs):
    """Печатает одновременно в консоль и в оригинальный stdout."""
    print(*args, **kwargs)
    if ORIGINAL_STDOUT:
        print(*args, file=ORIGINAL_STDOUT, **kwargs)
    if not getattr(_guard, "active", False):
        rep = _report()
        if rep is not None:
            rep.note(" ".join(str(a) for a in args))


def print_section(title):
    rep = _report()
    if rep is not None:
        rep.section(title)
    _guard.active = True
    try:
        dual_print(f"\n{'─' * 58}")
        dual_print(f"  ▸ {title}")
        dual_print(f"{'─' * 58}")
    finally:
        _guard.active = False


def print_field(label, value, indent=4):
    """Выводит поле, если значение непустое.

    'false' НЕ подавляется: для OSINT «disposable: False», «vpn: False» и т.п. —
    полезная информация, а не пустое значение.
    """
    if value is None:
        return
    v = str(value).strip()
    if v and v.lower() not in ("none", "null", "n/a"):
        rep = _report()
        if rep is not None:
            rep.field(label, v)
        _guard.active = True
        try:
            dual_print(f"{' ' * indent}{label:<26} {v}")
        finally:
            _guard.active = False


def print_summary(items: dict, title: str):
    """Итоговая таблица."""
    rep = _report()
    if rep is not None:
        rep.summary(title, items)
    _guard.active = True
    try:
        _print_summary_body(items, title)
    finally:
        _guard.active = False


def _print_summary_body(items: dict, title: str):
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  ✔ ИТОГ: {title}  ({len(items)} найдено)")
    dual_print(f"{'═' * 58}")
    if items:
        for k, v in sorted(items.items()):
            dual_print(f"    • {k:<22} {v}")
    else:
        dual_print("  Ничего не найдено.")
    dual_print(f"{'═' * 58}")
