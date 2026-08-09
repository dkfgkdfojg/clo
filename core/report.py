# core/report.py
"""Сбор результатов анализа в структуру и выгрузка в JSON + HTML.

Анализаторы уже гонят весь вывод через print_field/print_section/print_summary/
dual_print (core.utils). Эти хелперы дублируют данные сюда, поэтому сами
анализаторы менять не нужно. Активный отчёт живёт на время одного прогона:
begin() в начале, finish() в конце (см. gui/app.py).

Секреты не попадают в файл: значения ключей из config и query-параметры
key/token/secret вырезаются на входе.
"""

from __future__ import annotations

import html
import json
import re
import threading
import time
from datetime import datetime
from pathlib import Path

from config import API_KEYS

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

_SECRET_PARAM_RE = re.compile(
    r"(?i)([?&](?:api[_-]?key|access[_-]?key|key|token|access_token|secret)=)[^&\s]+"
)


def _redact(text: str) -> str:
    if not text:
        return text
    text = _SECRET_PARAM_RE.sub(r"\1***", text)
    for val in API_KEYS.values():
        if val and len(val) >= 6:
            text = text.replace(val, "***")
    return text


_DECORATION = set("─═•▸✔✖✓✗⚠ ")


def _is_decoration(line: str) -> bool:
    s = line.strip()
    return not s or all(ch in _DECORATION for ch in s)


class Report:
    def __init__(self, kind: str, target: str):
        self.kind = kind
        self.target = target
        self.started = time.time()
        self.finished: float | None = None
        self.sections: list[dict] = []
        self.summaries: list[dict] = []
        self._current: dict | None = None
        self._lock = threading.Lock()

    def _ensure_section(self) -> dict:
        if self._current is None:
            self._current = {"title": "Общее", "fields": [], "notes": []}
            self.sections.append(self._current)
        return self._current

    def section(self, title: str) -> None:
        with self._lock:
            sec = {"title": title, "fields": [], "notes": []}
            self.sections.append(sec)
            self._current = sec

    def field(self, label: str, value: str) -> None:
        with self._lock:
            self._ensure_section()["fields"].append(
                {"label": label, "value": _redact(str(value))}
            )

    def note(self, line: str) -> None:
        if _is_decoration(line):
            return
        with self._lock:
            self._ensure_section()["notes"].append(_redact(line.rstrip()))

    def summary(self, title: str, items: dict) -> None:
        with self._lock:
            self.summaries.append(
                {"title": title, "items": {k: _redact(str(v)) for k, v in items.items()}}
            )

    # ---- сериализация ----

    def to_dict(self) -> dict:
        end = self.finished or time.time()
        return {
            "kind": self.kind,
            "target": self.target,
            "started_at": datetime.fromtimestamp(self.started).isoformat(timespec="seconds"),
            "finished_at": datetime.fromtimestamp(end).isoformat(timespec="seconds"),
            "duration_sec": round(end - self.started, 1),
            "sections": self.sections,
            "summaries": self.summaries,
        }

    def _stem(self) -> str:
        safe = re.sub(r"[^\w.@-]+", "_", self.target)[:60].strip("_") or "target"
        ts = datetime.fromtimestamp(self.started).strftime("%Y%m%d_%H%M%S")
        return f"{self.kind}_{safe}_{ts}"

    def save(self, directory: Path | str = REPORTS_DIR) -> tuple[Path, Path]:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        stem = self._stem()
        json_path = directory / f"{stem}.json"
        html_path = directory / f"{stem}.html"
        json_path.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        html_path.write_text(self._render_html(), encoding="utf-8")
        try:
            build_index(directory)
        except Exception:
            pass
        return json_path, html_path

    def _render_html(self) -> str:
        d = self.to_dict()
        e = html.escape
        parts = [_HTML_HEAD.format(
            title=e(f"{d['kind']} — {d['target']}"),
            kind=e(d["kind"]),
            target=e(d["target"]),
            started=e(d["started_at"]),
            dur=e(str(d["duration_sec"])),
        )]

        for summ in d["summaries"]:
            if not summ["items"]:
                continue
            parts.append(f'<section class="card summary"><h2>{e(summ["title"])}</h2><table>')
            for k, v in summ["items"].items():
                parts.append(f"<tr><td class='k'>{e(str(k))}</td><td>{e(str(v))}</td></tr>")
            parts.append("</table></section>")

        for sec in d["sections"]:
            if not sec["fields"] and not sec["notes"]:
                continue
            parts.append(f'<section class="card"><h2>{e(sec["title"])}</h2>')
            if sec["fields"]:
                parts.append("<table>")
                for f in sec["fields"]:
                    val = e(str(f["value"]))
                    if re.match(r"https?://", str(f["value"])):
                        val = f'<a href="{val}" target="_blank" rel="noopener">{val}</a>'
                    parts.append(f"<tr><td class='k'>{e(str(f['label']))}</td><td>{val}</td></tr>")
                parts.append("</table>")
            if sec["notes"]:
                parts.append("<ul class='notes'>")
                for n in sec["notes"]:
                    parts.append(f"<li>{e(n)}</li>")
                parts.append("</ul>")
            parts.append("</section>")

        parts.append("</div></body></html>")
        return "".join(parts)


_HTML_HEAD = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{{--bg:#0f1117;--surface:#171a23;--border:#252a37;--text:#e6e8ee;--muted:#8b93a7;--accent:#7C8CFF;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:900px;margin:0 auto;padding:28px 18px}}
header{{border-bottom:1px solid var(--border);padding-bottom:16px;margin-bottom:20px}}
h1{{margin:0 0 6px;font-size:20px}}
h1 .tag{{color:var(--accent)}}
.meta{{color:var(--muted);font-size:12px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin-bottom:14px}}
.card h2{{margin:0 0 12px;font-size:14px;color:var(--accent);font-weight:600}}
.summary h2{{color:#3DDC97}}
table{{width:100%;border-collapse:collapse}}
td{{padding:5px 8px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word}}
td.k{{color:var(--muted);width:34%;white-space:nowrap}}
tr:last-child td{{border-bottom:none}}
a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
.notes{{margin:8px 0 0;padding-left:18px;color:var(--muted)}}
.notes li{{margin:2px 0}}
</style></head><body><div class="wrap">
<header><h1><span class="tag">{kind}</span> — {target}</h1>
<div class="meta">{started} · {dur} c</div></header>
"""


def build_index(directory: Path | str = REPORTS_DIR) -> Path:
    """Собрать reports/index.html — список всех отчётов с поиском по строке."""
    directory = Path(directory)
    rows = []
    for jf in sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            d = json.loads(jf.read_text(encoding="utf-8"))
        except Exception:
            continue
        htmlf = jf.with_suffix(".html").name
        rows.append({
            "kind": d.get("kind", "?"),
            "target": d.get("target", jf.stem),
            "when": d.get("finished_at", ""),
            "href": htmlf if (directory / htmlf).exists() else "",
        })
    # investigation_*.html не имеют json — добавим отдельно
    for hf in sorted(directory.glob("investigation_*.html"), key=lambda p: p.stat().st_mtime, reverse=True):
        rows.append({"kind": "Investigation", "target": hf.stem, "when": "", "href": hf.name})

    esc = html.escape
    trs = "".join(
        f'<tr data-s="{esc((r["kind"]+" "+r["target"]).lower())}">'
        f'<td>{esc(r["kind"])}</td>'
        f'<td>{"<a href=\""+esc(r["href"])+"\">"+esc(r["target"])+"</a>" if r["href"] else esc(r["target"])}</td>'
        f'<td class="muted">{esc(r["when"])}</td></tr>'
        for r in rows
    )
    page = _INDEX_TEMPLATE.format(count=len(rows), rows=trs)
    out = directory / "index.html"
    out.write_text(page, encoding="utf-8")
    return out


_INDEX_TEMPLATE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>clo — отчёты</title>
<style>
:root{{--bg:#0f1117;--surface:#171a23;--border:#252a37;--text:#e6e8ee;--muted:#8b93a7;--accent:#7C8CFF;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:900px;margin:0 auto;padding:28px 18px}}
h1{{font-size:20px}} h1 .tag{{color:var(--accent)}}
input{{width:100%;padding:9px 12px;margin:12px 0;background:var(--surface);border:1px solid var(--border);border-radius:8px;color:var(--text)}}
table{{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}}
td,th{{padding:8px 12px;border-bottom:1px solid var(--border);text-align:left}}
th{{color:var(--muted)}} a{{color:var(--accent);text-decoration:none}}
.muted{{color:var(--muted);font-size:12px}}
</style></head><body><div class="wrap">
<h1><span class="tag">clo</span> — отчёты ({count})</h1>
<input id="q" placeholder="фильтр по типу или цели…" oninput="f()">
<table><thead><tr><th>Модуль</th><th>Цель</th><th>Время</th></tr></thead>
<tbody id="t">{rows}</tbody></table>
<script>
function f(){{var q=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('#t tr').forEach(function(r){{
r.style.display=r.getAttribute('data-s').indexOf(q)>-1?'':'none';}});}}
</script>
</div></body></html>
"""


# ---- активный отчёт (один прогон за раз) ----

_active: Report | None = None
_active_lock = threading.Lock()


def begin(kind: str, target: str) -> Report:
    global _active
    with _active_lock:
        _active = Report(kind, target)
    return _active


def current() -> Report | None:
    return _active


def finish() -> Report | None:
    global _active
    with _active_lock:
        rep = _active
        _active = None
    if rep is not None:
        rep.finished = time.time()
    return rep
