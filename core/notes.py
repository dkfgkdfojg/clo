# core/notes.py
"""Заметки и теги по цели + оценка уверенности (confidence).

Хранилище — reports/notes.json, ключ = строка цели. Используется карточкой
цели в GUI, чтобы аналитик мог оставлять пометки прямо в ходе работы.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_FILE = Path(__file__).resolve().parent.parent / "reports" / "notes.json"
_lock = threading.Lock()


def _load() -> dict:
    try:
        return json.loads(_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(data: dict) -> None:
    _FILE.parent.mkdir(parents=True, exist_ok=True)
    _FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def get(target: str) -> dict:
    return _load().get(target, {"notes": [], "tags": []})


def add_note(target: str, text: str) -> None:
    text = text.strip()
    if not text:
        return
    with _lock:
        data = _load()
        entry = data.setdefault(target, {"notes": [], "tags": []})
        entry["notes"].append({"t": time.strftime("%Y-%m-%d %H:%M"), "text": text})
        _save(data)


def add_tag(target: str, tag: str) -> None:
    tag = tag.strip().lstrip("#")
    if not tag:
        return
    with _lock:
        data = _load()
        entry = data.setdefault(target, {"notes": [], "tags": []})
        if tag not in entry["tags"]:
            entry["tags"].append(tag)
        _save(data)


def confidence(matches: int) -> tuple[str, int]:
    """Грубая оценка уверенности по числу совпадений. Возвращает (метка, %).

    Это эвристика для приоритезации, а не доказательство принадлежности.
    """
    pct = max(5, min(95, matches * 12))
    if matches >= 6:
        return "высокая", pct
    if matches >= 3:
        return "средняя", pct
    return "низкая", pct
