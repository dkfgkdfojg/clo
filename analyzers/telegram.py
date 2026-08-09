# analyzers/telegram.py
"""
Развитый Telegram-анализ.

Два уровня:
  1. Парсинг t.me (без ключей, работает всегда) — тип сущности (пользователь/
     бот/канал/группа), имя, bio, число подписчиков/участников, verified,
     аватар. Для каналов через t.me/s/<name>: последние посты, диапазон
     ID постов и оценка удалённых (gaps), forwarded-источники, дата активности.
  2. Опциональный Telethon-тир (если заданы TELEGRAM_API_ID/HASH и есть готовая
     сессия): username<->id, флаги premium/scam/fake/verified/bot, phone->user
     через импорт контакта, похожие каналы. Никакого интерактивного логина в
     рантайме — если сессия не авторизована, тир пропускается с подсказкой.

За образец взяты maltego-telegram (vognik), telegram-osint (yusiqo) и
разбор t.me-разметки; реализация переписана под этот тул.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from config import API_KEYS
from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger

TME = "https://t.me/{}"
TME_PREVIEW = "https://t.me/s/{}"

# Каталоги-агрегаторы: проверяем только наличие страницы, без глубокого парсинга.
DIRECTORIES = [
    ("TGStat", "https://tgstat.ru/channel/@{}"),
    ("Telemetr", "https://telemetr.io/en/channels/@{}"),
    ("Telemetrio", "https://telemetr.me/@{}"),
]


@dataclass
class TgTarget:
    kind: str          # "username" | "phone" | "invite"
    value: str         # нормализованное значение (username без @, телефон с +, код инвайта)
    raw: str


def _classify(target: str) -> TgTarget:
    """Разобрать ввод: @username, ссылку t.me, телефон или инвайт."""
    raw = target.strip()
    t = raw

    # вытащить хвост из ссылки t.me / telegram.me
    m = re.search(r"(?:t\.me|telegram\.me)/(.+)$", t, re.I)
    if m:
        t = m.group(1)

    t = t.strip("/")

    # инвайт: joinchat/XXX или +XXX (но не телефон)
    if t.lower().startswith("joinchat/"):
        return TgTarget("invite", t.split("/", 1)[1], raw)
    if t.startswith("+") and not re.fullmatch(r"\+?\d[\d\s()-]{6,}", t):
        return TgTarget("invite", t[1:], raw)

    # телефон
    digits = re.sub(r"[\s()-]", "", t)
    if re.fullmatch(r"\+?\d{7,15}", digits):
        return TgTarget("phone", digits if digits.startswith("+") else "+" + digits, raw)

    # username
    return TgTarget("username", t.lstrip("@").split("/", 1)[0].split("?", 1)[0], raw)


# ---------------------------------------------------------------------------
# Парсинг t.me
# ---------------------------------------------------------------------------


@dataclass
class TmeProfile:
    username: str
    entity: str = "unknown"          # user | bot | channel | group | unknown
    title: str = ""
    bio: str = ""
    photo: str = ""
    count: str = ""                  # подписчики/участники, как на странице
    verified: bool = False
    exists: bool = False


def _parse_tme(username: str, session) -> TmeProfile:
    prof = TmeProfile(username=username)
    try:
        r = safe_get(session, TME.format(username), timeout=12)
    except Exception as exc:
        logger.debug("t.me fetch: %s", exc)
        return prof
    if r.status_code != 200:
        return prof
    soup = BeautifulSoup(r.text, "lxml")

    # страница-заглушка (несуществующий юзер) не содержит tgme_page
    page = soup.select_one(".tgme_page")
    title_el = soup.select_one(".tgme_page_title")
    if not page and not title_el:
        return prof
    prof.exists = True

    if title_el:
        prof.title = title_el.get_text(" ", strip=True)
    desc = soup.select_one(".tgme_page_description")
    if desc:
        prof.bio = desc.get_text("\n", strip=True)
    img = soup.select_one(".tgme_page_photo_image img")
    if img and img.get("src"):
        prof.photo = img["src"]
    if soup.select_one(".verified-icon"):
        prof.verified = True

    extra = soup.select_one(".tgme_page_extra")
    extra_txt = extra.get_text(" ", strip=True).lower() if extra else ""
    action = soup.select_one(".tgme_action_button_new, .tgme_action_button_label")
    action_txt = action.get_text(" ", strip=True).lower() if action else ""

    if "subscriber" in extra_txt or "подписчик" in extra_txt:
        prof.entity = "channel"
        prof.count = extra.get_text(" ", strip=True)
    elif "member" in extra_txt or "участник" in extra_txt:
        prof.entity = "group"
        prof.count = extra.get_text(" ", strip=True)
    elif username.lower().endswith("bot") or "start bot" in action_txt:
        prof.entity = "bot"
    else:
        prof.entity = "user"
    return prof


@dataclass
class ChannelActivity:
    last_date: str = ""
    first_post_id: int = 0
    last_post_id: int = 0
    seen_posts: int = 0
    forwarded: list[str] = field(default_factory=list)


def _parse_channel_activity(username: str, session) -> ChannelActivity | None:
    """t.me/s/<name>: последние посты, диапазон ID (для оценки удалённых) и
    источники репостов."""
    r = safe_get(session, TME_PREVIEW.format(username), timeout=12)
    if r.status_code != 200:
        return None
    soup = BeautifulSoup(r.text, "lxml")
    msgs = soup.select(".tgme_widget_message[data-post]")
    if not msgs:
        return None

    act = ChannelActivity()
    ids: list[int] = []
    for m in msgs:
        post = m.get("data-post", "")
        pid = post.split("/")[-1]
        if pid.isdigit():
            ids.append(int(pid))
    if ids:
        act.first_post_id = min(ids)
        act.last_post_id = max(ids)
        act.seen_posts = len(set(ids))

    last_time = soup.select(".tgme_widget_message_date time[datetime]")
    if last_time:
        act.last_date = last_time[-1].get("datetime", "")

    for fwd in soup.select(".tgme_widget_message_forwarded_from_name"):
        href = fwd.get("href", "")
        name = fwd.get_text(" ", strip=True)
        src = f"{name} ({href})" if href else name
        if src and src not in act.forwarded:
            act.forwarded.append(src)
    return act


def _check_directories(username: str, session, results: dict) -> None:
    print_section("Каталоги / статистика")
    for name, tpl in DIRECTORIES:
        url = tpl.format(username)
        try:
            r = safe_get(session, url, timeout=10)
            if r.status_code == 200 and "не найден" not in r.text.lower():
                print_field(name, url)
                results[name] = url
        except Exception as exc:
            logger.debug("%s: %s", name, exc)


# ---------------------------------------------------------------------------
# Опциональный Telethon-тир
# ---------------------------------------------------------------------------


def _session_path() -> str:
    import os
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), ".tg_session")


def _telethon_client():
    """Вернуть подключённый авторизованный клиент или None.

    Никогда не запрашивает код интерактивно: если сессия не авторизована,
    возвращает None — пусть пользователь один раз залогинится через CLI.
    """
    api_id = API_KEYS.get("TELEGRAM_API_ID")
    api_hash = API_KEYS.get("TELEGRAM_API_HASH")
    if not api_id or not api_hash:
        return None
    try:
        from telethon.sync import TelegramClient
    except ImportError:
        dual_print("  [i] Telethon-тир пропущен: pip install telethon")
        return None
    try:
        client = TelegramClient(_session_path(), int(api_id), api_hash)
        client.connect()
        if not client.is_user_authorized():
            dual_print(
                "  [i] Telethon: нет авторизованной сессии. Разово залогиньтесь "
                "командой: python -m analyzers.telegram --login"
            )
            client.disconnect()
            return None
        return client
    except Exception as exc:
        logger.debug("telethon connect: %s", exc)
        return None


def _flags_line(entity) -> str:
    flags = []
    for name in ("verified", "scam", "fake", "premium", "bot", "restricted"):
        if getattr(entity, name, False):
            flags.append(name)
    return ", ".join(flags) if flags else "—"


def _telethon_username(client, username: str, results: dict) -> None:
    from telethon import functions
    print_section("Telethon: сущность")
    try:
        ent = client.get_entity(username)
    except Exception as exc:
        dual_print(f"  [!] get_entity: {exc}")
        return
    print_field("ID", str(getattr(ent, "id", "")))
    results["tg_id"] = str(getattr(ent, "id", ""))
    print_field("Флаги", _flags_line(ent))
    title = getattr(ent, "title", None) or " ".join(
        x for x in (getattr(ent, "first_name", ""), getattr(ent, "last_name", "")) if x
    )
    print_field("Имя", title)

    # похожие каналы — только для каналов
    if getattr(ent, "broadcast", False):
        try:
            rec = client(functions.channels.GetChannelRecommendationsRequest(channel=ent))
            names = [f"@{c.username}" for c in rec.chats if getattr(c, "username", None)]
            if names:
                print_field("Похожие каналы", ", ".join(names[:15]))
                results["tg_similar"] = ", ".join(names[:15])
        except Exception as exc:
            logger.debug("recommendations: %s", exc)

    _telethon_gifts(client, ent, results)


def _telethon_gifts(client, entity, results: dict) -> None:
    """Подарки профиля и связь по отправителям.

    Публичные звёздные подарки на профиле нередко подписаны отправителем —
    это готовые связи между аккаунтами. Аноним/скрытые пропускаем.
    """
    from collections import Counter
    from telethon.tl import functions

    fn = getattr(getattr(functions, "payments", None), "GetSavedStarGiftsRequest", None)
    if fn is None:
        return  # версия Telethon без star gifts — молча пропускаем
    print_section("Подарки (связь по отправителям)")
    try:
        res = client(fn(peer=entity, offset="", limit=100))
    except Exception as exc:
        dual_print(f"  [!] gifts: {exc}")
        return

    gifts = getattr(res, "gifts", []) or []
    if not gifts:
        dual_print("  [–] Подарков нет или скрыты настройками.")
        return

    total_stars = 0
    senders: Counter = Counter()
    anon = 0
    for g in gifts:
        star = getattr(getattr(g, "gift", None), "stars", 0) or 0
        total_stars += star
        frm = getattr(g, "from_id", None)
        uid = getattr(frm, "user_id", None)
        if uid:
            senders[uid] += 1
        elif getattr(g, "name_hidden", False) or frm is None:
            anon += 1

    print_field("Подарков всего", len(gifts))
    if total_stars:
        print_field("Сумма звёзд", total_stars)
    if anon:
        print_field("Анонимных", anon)
    results["Подарков"] = str(len(gifts))

    if senders:
        dual_print("  Отправители (связи):")
        for uid, cnt in senders.most_common(15):
            label = str(uid)
            try:
                s = client.get_entity(uid)
                label = f"@{s.username}" if getattr(s, "username", None) else \
                    " ".join(x for x in (getattr(s, "first_name", ""),
                                         getattr(s, "last_name", "")) if x) or str(uid)
            except Exception:
                pass
            dual_print(f"    ← {label}: {cnt} подарк(ов)")
        results["Дарителей"] = str(len(senders))


def _telethon_phone(client, phone: str, results: dict) -> None:
    from telethon.tl import types
    from telethon.tl.functions.contacts import ImportContactsRequest, DeleteContactsRequest
    print_section("Telethon: поиск по телефону")
    try:
        contact = types.InputPhoneContact(client_id=0, phone=phone, first_name="x", last_name="")
        res = client(ImportContactsRequest([contact]))
        if not res.users:
            dual_print("  [!] По номеру ничего не найдено (или скрыто настройками).")
            return
        u = res.users[0]
        uname = f"@{u.username}" if u.username else "—"
        print_field("ID", str(u.id))
        print_field("Username", uname)
        print_field("Имя", " ".join(x for x in (u.first_name or "", u.last_name or "") if x))
        print_field("Флаги", _flags_line(u))
        results["tg_id"] = str(u.id)
        results["tg_username"] = uname
        # не оставляем мусор в контактах аккаунта
        try:
            client(DeleteContactsRequest(id=[u.id]))
        except Exception:
            pass
    except Exception as exc:
        dual_print(f"  [!] import_contacts: {exc}")


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------


def analyze_telegram_full(target: str) -> None:
    tgt = _classify(target)
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] TELEGRAM: {tgt.raw}  (тип: {tgt.kind})")
    dual_print(f"{'═' * 58}")

    results: dict[str, str] = {}
    session = get_session()

    if tgt.kind == "invite":
        print_section("Инвайт")
        url = f"https://t.me/+{tgt.value}"
        print_field("Ссылка", url)
        prof = _parse_tme("+" + tgt.value, session)
        if prof.exists:
            print_field("Название", prof.title)
            print_field("Описание", prof.bio)
            print_field("Участников", prof.count)
            results["invite"] = url
        else:
            dual_print("  [!] Инвайт недоступен или истёк.")

    elif tgt.kind == "username":
        u = tgt.value
        print_section("t.me — профиль")
        prof = _parse_tme(u, session)
        if not prof.exists:
            dual_print("  [!] Публичной страницы t.me нет (приватный/несуществующий).")
        else:
            print_field("Тип", prof.entity)
            print_field("Имя", prof.title)
            print_field("Verified", "да" if prof.verified else "нет")
            if prof.bio:
                print_field("Bio/описание", prof.bio)
            if prof.count:
                print_field("Аудитория", prof.count)
            if prof.photo:
                print_field("Аватар", prof.photo)
            results["Тип"] = prof.entity
            results["URL"] = TME.format(u)

            if prof.entity in ("channel", "group"):
                act = _parse_channel_activity(u, session)
                if act:
                    print_section("Активность канала")
                    if act.last_date:
                        print_field("Последний пост", act.last_date)
                    if act.last_post_id:
                        print_field("Диапазон ID постов", f"{act.first_post_id}–{act.last_post_id}")
                        gaps = act.last_post_id - act.first_post_id + 1 - act.seen_posts
                        if gaps > 0:
                            print_field("Разрывов в нумерации", f"~{gaps} (удалённые/сервисные)")
                    if act.forwarded:
                        print_field("Репостит из", "; ".join(act.forwarded[:10]))
                        results["Репосты из"] = "; ".join(act.forwarded[:5])

        _check_directories(u, session, results)

        client = _telethon_client()
        if client is not None:
            try:
                _telethon_username(client, u, results)
            finally:
                client.disconnect()

    elif tgt.kind == "phone":
        print_section("Поиск по телефону")
        dual_print("  [i] Парсинг t.me по номеру невозможен — нужен Telethon-тир.")
        client = _telethon_client()
        if client is not None:
            try:
                _telethon_phone(client, tgt.value, results)
            finally:
                client.disconnect()

    print_summary(results, f"Telegram {tgt.raw}")


def _cli_login() -> None:
    """Разовый интерактивный логин для создания .tg_session (запуск из CLI)."""
    api_id = API_KEYS.get("TELEGRAM_API_ID")
    api_hash = API_KEYS.get("TELEGRAM_API_HASH")
    if not api_id or not api_hash:
        print("Заполни TELEGRAM_API_ID и TELEGRAM_API_HASH в .env")
        return
    from telethon.sync import TelegramClient
    with TelegramClient(_session_path(), int(api_id), api_hash) as client:
        me = client.get_me()
        print(f"Авторизован как {me.first_name} (@{me.username}) id={me.id}")


if __name__ == "__main__":
    import sys
    if "--login" in sys.argv:
        _cli_login()
    elif len(sys.argv) > 1:
        analyze_telegram_full(sys.argv[1])
    else:
        print("usage: python -m analyzers.telegram <@username|t.me/...|+phone>  [--login]")
