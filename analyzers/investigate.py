# analyzers/investigate.py
"""Корреляция и пивотинг: один ввод → цепочка связанных модулей → сводный отчёт.

Запускаем профильный модуль, вытаскиваем из его результата новые сущности
(email, github, telegram, discord, домен, IP) и автоматически прогоняем модули
по ним. Всё сводится в один investigation-отчёт с графом связей.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from datetime import datetime

from analyzers.phone import analyze_phone_combo
from analyzers.username import analyze_username_combo
from analyzers.email import analyze_email_leaks
from analyzers.discord import analyze_discord
from analyzers.telegram import analyze_telegram_full
from analyzers.github import analyze_github
from analyzers.ip import analyze_ip_basic
from analyzers.domain import analyze_domain
from core import report
from core.report import REPORTS_DIR
from core.utils import dual_print, print_section, logger

MODULE = {
    "phone": (analyze_phone_combo, "Телефон"),
    "username": (analyze_username_combo, "Username"),
    "email": (analyze_email_leaks, "Email"),
    "discord": (analyze_discord, "Discord"),
    "telegram": (analyze_telegram_full, "Telegram"),
    "github": (analyze_github, "GitHub"),
    "ip": (analyze_ip_basic, "IP"),
    "domain": (analyze_domain, "Домен"),
}

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_GITHUB_RE = re.compile(r"github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)", re.I)
_TME_RE = re.compile(r"t\.me/([A-Za-z0-9_]{4,32})", re.I)
_DISCORD_RE = re.compile(r"\b(\d{17,20})\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# домены/логины, которые не стоит раскручивать как отдельные сущности
_SKIP_DOMAINS = {
    "gmail.com", "googleusercontent.com", "google.com", "outlook.com", "hotmail.com",
    "yahoo.com", "icloud.com", "protonmail.com", "mail.ru", "yandex.ru",
}
_SKIP_GH = {
    "sponsors", "features", "about", "pricing", "login", "join", "settings",
    "marketplace", "explore", "topics", "search", "orgs", "users", "apps",
}


@dataclass
class Entity:
    kind: str
    value: str
    source: str          # какой модуль его выдал


@dataclass
class SubReport:
    kind: str
    label: str
    target: str
    rep: report.Report
    html_name: str = ""
    entities: list[Entity] = field(default_factory=list)


def _classify(target: str) -> str:
    t = target.strip()
    if "@" in t and "." in t.split("@")[-1]:
        return "email"
    if _IPV4_RE.fullmatch(t):
        return "ip"
    if re.fullmatch(r"\d{17,20}", t):
        return "discord"
    if re.fullmatch(r"\+?\d[\d\s()-]{6,}", t):
        return "phone"
    if "t.me/" in t or t.startswith("@"):
        return "telegram"
    if "github.com/" in t:
        return "github"
    if re.fullmatch(r"[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+", t) and " " not in t:
        return "domain"
    return "username"


def _extract(rep: report.Report, self_value: str) -> list[Entity]:
    """Достать пивот-сущности из полей/заметок отчёта."""
    blob_parts: list[str] = []
    for sec in rep.sections:
        for f in sec["fields"]:
            blob_parts.append(str(f["value"]))
        blob_parts.extend(sec["notes"])
    for s in rep.summaries:
        blob_parts.extend(str(v) for v in s["items"].values())
    blob = "\n".join(blob_parts)

    found: dict[tuple, Entity] = {}

    def add(kind, value, src=rep.kind):
        value = value.strip().lower() if kind in ("email", "domain", "github") else value.strip()
        if not value or value == self_value.lower():
            return
        found.setdefault((kind, value), Entity(kind, value, src))

    for m in _EMAIL_RE.findall(blob):
        add("email", m)
        dom = m.split("@")[-1].lower()
        if dom not in _SKIP_DOMAINS:
            add("domain", dom)
    for m in _GITHUB_RE.findall(blob):
        if m.lower() not in _SKIP_GH:
            add("github", m)
    for m in _TME_RE.findall(blob):
        add("telegram", m)
    for m in _IPV4_RE.findall(blob):
        add("ip", m)
    for m in _DISCORD_RE.findall(blob):
        add("discord", m)
    return list(found.values())


def investigate(target: str, max_pivots: int = 6) -> None:
    kind = _classify(target)
    dual_print(f"\n{'#' * 58}")
    dual_print(f"  РАССЛЕДОВАНИЕ: {target}  (старт: {kind})")
    dual_print(f"{'#' * 58}")

    subs: list[SubReport] = []
    done: set[tuple] = {(kind, target.strip().lower())}
    queue: list[tuple[str, str, str]] = [(kind, target, "ввод")]
    pivots_used = 0

    while queue:
        k, val, src = queue.pop(0)
        if k not in MODULE:
            continue
        func, label = MODULE[k]
        print_section(f"[{label}] {val}  ← {src}")
        rep = report.begin(label, val)
        try:
            func(val)
        except Exception as exc:
            logger.debug("investigate %s(%s): %s", k, val, exc)
            dual_print(f"  [!] {label}: {exc}")
        report.finish()
        try:
            _, html_path = rep.save()
            html_name = html_path.name
        except Exception:
            html_name = ""
        sub = SubReport(k, label, val, rep, html_name)
        sub.entities = _extract(rep, val)
        subs.append(sub)

        # ставим в очередь новые сущности (только с первичного уровня)
        if src == "ввод":
            for ent in sub.entities:
                key = (ent.kind, ent.value)
                if key in done or ent.kind not in MODULE:
                    continue
                if pivots_used >= max_pivots:
                    break
                done.add(key)
                queue.append((ent.kind, ent.value, f"{label}"))
                pivots_used += 1

    _write_investigation(target, kind, subs)


def _write_investigation(target: str, kind: str, subs: list[SubReport]) -> None:
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  ✔ Модулей отработано: {len(subs)}")
    all_ent = {(e.kind, e.value): e for s in subs for e in s.entities}
    dual_print(f"  ✔ Связанных сущностей: {len(all_ent)}")
    dual_print(f"{'═' * 58}")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^\w.@-]+", "_", target)[:50].strip("_") or "target"
    out = REPORTS_DIR / f"investigation_{safe}_{ts}.html"
    out.write_text(_render(target, kind, subs, all_ent), encoding="utf-8")
    dual_print(f"[✓] Сводный отчёт: {out}")


def _render(target: str, kind: str, subs: list[SubReport], all_ent: dict) -> str:
    e = html.escape
    # граф связей (mermaid)
    lines = ["graph LR", f'  ROOT["{e(target)}"]:::root']
    for i, (key, ent) in enumerate(all_ent.items()):
        nid = f"E{i}"
        lines.append(f'  {nid}["{e(ent.kind)}: {e(ent.value)}"]')
        lines.append(f"  ROOT --> {nid}")
    graph = "\n".join(lines)

    rows = "".join(
        f"<tr><td>{e(ent.kind)}</td><td>{e(ent.value)}</td><td>{e(ent.source)}</td></tr>"
        for ent in all_ent.values()
    ) or "<tr><td colspan=3>—</td></tr>"

    mods = "".join(
        f'<li><span class="badge">{e(s.label)}</span> {e(s.target)}'
        + (f' — <a href="{e(s.html_name)}">отчёт</a>' if s.html_name else "")
        + f' <span class="muted">({len(s.entities)} связей)</span></li>'
        for s in subs
    )

    return _TEMPLATE.format(
        title=e(f"Расследование: {target}"),
        target=e(target),
        kind=e(kind),
        n_mods=len(subs),
        n_ent=len(all_ent),
        graph=graph,
        rows=rows,
        mods=mods,
    )


_TEMPLATE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{{--bg:#0f1117;--surface:#171a23;--border:#252a37;--text:#e6e8ee;--muted:#8b93a7;--accent:#7C8CFF;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1000px;margin:0 auto;padding:28px 18px}}
h1{{font-size:20px;margin:0 0 4px}} h1 .tag{{color:var(--accent)}}
.meta{{color:var(--muted);font-size:12px;margin-bottom:20px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin-bottom:14px}}
.card h2{{margin:0 0 12px;font-size:14px;color:var(--accent)}}
table{{width:100%;border-collapse:collapse}}
td,th{{padding:6px 8px;border-bottom:1px solid var(--border);text-align:left;word-break:break-word}}
th{{color:var(--muted);font-weight:600}}
ul{{list-style:none;padding:0;margin:0}} li{{padding:5px 0;border-bottom:1px solid var(--border)}}
.badge{{background:#232838;color:var(--accent);border-radius:6px;padding:1px 8px;font-size:12px;margin-right:6px}}
.muted{{color:var(--muted);font-size:12px}}
a{{color:var(--accent)}}
.mermaid{{background:#0c0e14;border-radius:10px;padding:10px;overflow-x:auto}}
</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>document.addEventListener('DOMContentLoaded',()=>{{if(window.mermaid)mermaid.initialize({{startOnLoad:true,theme:'dark'}});}});</script>
</head><body><div class="wrap">
<h1><span class="tag">Расследование</span> {target}</h1>
<div class="meta">старт: {kind} · модулей: {n_mods} · связанных сущностей: {n_ent}</div>
<section class="card"><h2>Граф связей</h2><pre class="mermaid">{graph}</pre></section>
<section class="card"><h2>Связанные сущности</h2>
<table><tr><th>Тип</th><th>Значение</th><th>Источник</th></tr>{rows}</table></section>
<section class="card"><h2>Модули и отчёты</h2><ul>{mods}</ul></section>
</div></body></html>
"""


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        investigate(sys.argv[1])
    else:
        print("usage: python -m analyzers.investigate <target>")
