# config.py
import os
from dotenv import load_dotenv

load_dotenv()

# ----- API КЛЮЧИ -----
API_KEYS = {
    "SHODAN": os.getenv("SHODAN_API_KEY", ""),
    "IPINFO": os.getenv("IPINFO_API_KEY", ""),
    "EMAILREP": os.getenv("EMAILREP_API_KEY", ""),
    "INTELX": os.getenv("INTELX_API_KEY", ""),
    "NUMVERIFY": os.getenv("NUMVERIFY_API_KEY", ""),
    # Discord: бот-токен даёт официальный /users/{id} и резолв инвайтов.
    # Без него discord-модуль падает на скрейперы (best-effort).
    "DISCORD_BOT_TOKEN": os.getenv("DISCORD_BOT_TOKEN", ""),
    # Telegram: api_id/api_hash включают опциональный Telethon-тир
    # (username<->id, phone->user, similar channels, sticker-деанон).
    # Без них telegram-модуль работает чисто на парсинге t.me.
    "TELEGRAM_API_ID": os.getenv("TELEGRAM_API_ID", ""),
    "TELEGRAM_API_HASH": os.getenv("TELEGRAM_API_HASH", ""),
    # GitHub: без токена лимит 60 запросов/час, с токеном — 5000/час.
    "GITHUB_TOKEN": os.getenv("GITHUB_TOKEN", ""),
}

# ----- БЛЭКЛИСТЫ САЙТОВ (для фильтрации URL) -----
BLACKLIST_SITES = [
    "op.gg",
    "leagueoflegends",
    "chaturbate",
    "adultfriendfinder",
    "hi5",
    "interpals",
    "weedmaps",
    "mercado",
    "kaskus",
    "getmyuni",
    "bibsonomy",
    "hashnode",
    "kinja",
    "wikimapia",
    "authorstream",
    "forums.bulbagarden.net",
    "forums.serebii.net",
    "blu-ray.com",
    "techpowerup.com/forums/members/",
    "forum.ixbt.com/users.cgi",
    "apple.com/profile",
    "kaggle",
    "roblox.com/user.aspx",
    "3ddd.ru",
    "picsart.com",
    "livemaster.ru",
    "flamp.ru",
    "igromani",
    "igromania",
]

# ----- САЙТЫ, ВСЕГДА ОТВЕЧАЮЩИЕ 200 (нужна GET-проверка) -----
ALWAYS_200_SITES = [
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
]

# ----- РЕГУЛЯРКИ ДЛЯ ОШИБОЧНЫХ СТРАНИЦ -----
ERROR_PATTERNS = [
    r"not\s*found",
    r"doesn\'?t\s*exist",
    r"no\s*results?",
    r"could\s*not\s*find",
    r"no\s*member",
    r"invalid\s*user",
    r"user\s*not\s*found",
    r"the\s*specified\s*user\s*does\s*not\s*exist",
    r"this\s*user\s*has\s*not\s*registered",
    r"no\s*such\s*user",
    r"nothing\s*found",
    r"0\s*results?",
    r"не\s*найден",
    r"пользователь\s*не\s*найден",
    r"нет\s*результатов",
    r"ничего\s*не\s*найдено",
    r"страница\s*не\s*найдена",
    r"no\s*data",
    r"no\s*posts?",
    r"no\s*activity",
    r"account\s*(has\s*been)?\s*(deleted|suspended|banned)",
    r"account\s*not\s*found",
    r"page\s*not\s*found",
]

# ----- ПАТТЕРНЫ ДЛЯ ПОИСКОВЫХ URL (исключаем) -----
SEARCH_URL_PATTERNS = [
    r"[?&]q=",
    r"/search\b",
    r"/find\b",
    r"/memberlist\b",
    r"/member\.php\?action=",
    r"/users\?",
]

# ----- ДОПОЛНИТЕЛЬНЫЕ ПЛАТФОРМЫ (для username) -----
EXTRA_PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Medium": "https://medium.com/@{}",
    "DeviantArt": "https://www.deviantart.com/{}",
    "Flickr": "https://www.flickr.com/people/{}",
    "Patreon": "https://www.patreon.com/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Bandcamp": "https://{}.bandcamp.com",
    "Keybase": "https://keybase.io/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "ProductHunt": "https://www.producthunt.com/@{}",
    "Bitbucket": "https://bitbucket.org/{}",
    "GitLab": "https://gitlab.com/{}",
    "Codepen": "https://codepen.io/{}",
    "Replit": "https://replit.com/@{}",
    "VK": "https://vk.com/{}",
    "OK": "https://ok.ru/{}",
    "Habr": "https://habr.com/ru/users/{}/",
    "Pikabu": "https://pikabu.ru/@{}",
    "LiveJournal": "https://{}.livejournal.com",
    "Gravatar": "https://www.gravatar.com/{}",
    "SourceForge": "https://sourceforge.net/u/{}/profile",
    "ReverbNation": "https://www.reverbnation.com/{}",
    "Blogger": "https://{}.blogspot.com",
    "Tumblr": "https://{}.tumblr.com",
}
