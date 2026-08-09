# core/cache.py
"""Кэш HTTP-ответов и троттлинг по хостам.

Кэш — диск + TTL, чтобы не дёргать один и тот же URL повторно между прогонами.
Троттлинг — минимальный интервал между запросами к одному хосту, чтобы не
ловить rate-limit на агрессивных источниках (crt.sh, binlist, hackertarget).
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from core.http import safe_get
from core.utils import logger

CACHE_DIR = Path(__file__).resolve().parent.parent / "reports" / ".httpcache"

# Минимальный интервал между запросами к хосту (сек). 0 — без ограничения.
HOST_INTERVAL = {
    "crt.sh": 2.0,
    "lookup.binlist.net": 2.0,
    "api.hackertarget.com": 1.5,
    "api.threatminer.org": 1.5,
    "rdap.org": 1.0,
}

_last_hit: dict[str, float] = {}
_lock = threading.Lock()


def throttle(url: str) -> None:
    host = urlsplit(url).netloc
    interval = HOST_INTERVAL.get(host, 0)
    if not interval:
        return
    with _lock:
        wait = interval - (time.time() - _last_hit.get(host, 0))
        if wait > 0:
            time.sleep(wait)
        _last_hit[host] = time.time()


def _path(url: str) -> Path:
    return CACHE_DIR / (hashlib.sha1(url.encode()).hexdigest() + ".json")


def cached_json(session, url, ttl=900, **kwargs):
    """GET с диск-кэшем и троттлингом; возвращает разобранный JSON или None.

    ttl — время жизни кэша в секундах (по умолчанию 15 минут).
    """
    p = _path(url)
    if p.exists() and (time.time() - p.stat().st_mtime) < ttl:
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    throttle(url)
    try:
        r = safe_get(session, url, **kwargs)
    except Exception as exc:
        logger.debug("cached_json fetch %s: %s", url, exc)
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
    return data
