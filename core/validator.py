# core/validator.py
"""Валидаторы, экстракторы и хелперы для проверки входных данных, URL и текста.

Все функции работают с str, возвращают bool или list[str].
Для производительности все регулярные выражения прекомпилированы.
"""

from __future__ import annotations

import ipaddress
import os
import re
import uuid
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from config import BLACKLIST_SITES, SEARCH_URL_PATTERNS, ERROR_PATTERNS

# ============================================================================
# ПРЕКОМПИЛИРОВАННЫЕ РЕГУЛЯРКИ
# ============================================================================

# --- Basic ---
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
_PHONE_RE = re.compile(r"^\+?[1-9]\d{6,14}$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,30}$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# --- UUID / Hashes ---
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_MD5_RE = re.compile(r"^[a-f0-9]{32}$", re.I)
_SHA1_RE = re.compile(r"^[a-f0-9]{40}$", re.I)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.I)
_SHA512_RE = re.compile(r"^[a-f0-9]{128}$", re.I)

# --- Discord ---
_DISCORD_SNOWFLAKE_RE = re.compile(r"^\d{17,20}$")
_DISCORD_TOKEN_RE = re.compile(r"^[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,38}$")
_DISCORD_INVITE_RE = re.compile(
    r"(?:discord\.(?:com|gg|app|me|media|new)|discord(?:app)?\.com/invite)/[\w-]+", re.I
)
_DISCORD_USER_MENTION_RE = re.compile(r"<@!?(\d{17,20})>")
_DISCORD_CHANNEL_MENTION_RE = re.compile(r"<#(\d{17,20})>")
_DISCORD_ROLE_MENTION_RE = re.compile(r"<@&(\d{17,20})>")
_DISCORD_EMOJI_RE = re.compile(r"<a?:(\w+):(\d{17,20})>")

# --- Telegram ---
_TELEGRAM_TOKEN_RE = re.compile(r"^\d{8,10}:[\w-]{35}$")
_TELEGRAM_CHAT_ID_RE = re.compile(r"^-?\d{5,}$")
_TELEGRAM_USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{3,31}$")

# --- Crypto ---
_BTC_ADDRESS_RE = re.compile(
    r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-zA-HJ-NP-Z0-9]{39,59}$"
)
_ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_TRX_ADDRESS_RE = re.compile(r"^T[a-zA-Z0-9]{33}$")
_SOL_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

# --- Network ---
_MAC_ADDRESS_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
_SSH_KEY_RE = re.compile(
    r"^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp\d{3})\s+A-Za-z0-9+/=+"
)

# --- Social / API Keys ---
_TWITTER_HANDLE_RE = re.compile(r"@?\w{1,15}$")
_INSTAGRAM_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.]{1,30}$")
_GITHUB_TOKEN_RE = re.compile(r"^gh[pousr]_[A-Za-z0-9_]{36,255}$")
_AWS_KEY_RE = re.compile(r"^AKIA[0-9A-Z]{16}$")
_AWS_SECRET_RE = re.compile(r"^[A-Za-z0-9/+=]{40}$")
_SLACK_TOKEN_RE = re.compile(r"^xox[baprs]-[\w-]{10,}$")
_STRIPE_KEY_RE = re.compile(r"^(?:sk|pk)_(?:test_|live_)?[A-Za-z0-9]{24,}$")

# --- Extraction ---
_EMAIL_EXTRACT_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_URL_EXTRACT_RE = re.compile(r'https?://[^\s<>"\'()]+')
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# --- MIME types ---
_MIME_EXTENSIONS: dict[str, str] = {
    # Images
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".bmp": "image/bmp",
    ".tiff": "image/tiff",
    # Documents
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".csv": "text/csv",
    ".json": "application/json",
    ".xml": "application/xml",
    ".yaml": "application/x-yaml",
    ".yml": "application/x-yaml",
    # Archives
    ".zip": "application/zip",
    ".rar": "application/vnd.rar",
    ".tar": "application/x-tar",
    ".gz": "application/gzip",
    ".7z": "application/x-7z-compressed",
    # Code
    ".py": "text/x-python",
    ".js": "text/javascript",
    ".ts": "text/typescript",
    ".html": "text/html",
    ".htm": "text/html",
    ".css": "text/css",
    ".php": "text/x-php",
    ".sql": "text/x-sql",
    ".sh": "text/x-shellscript",
    ".bat": "application/x-bat",
    ".ps1": "text/x-powershell",
    # Media
    ".mp4": "video/mp4",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".avi": "video/x-msvideo",
    ".mkv": "video/x-matroska",
    # Other
    ".exe": "application/x-msdownload",
    ".dll": "application/x-msdownload",
    ".apk": "application/vnd.android.package-archive",
    ".dmg": "application/x-apple-diskimage",
    ".iso": "application/x-iso9660-image",
}

# --- Social network domain patterns (precompiled) ---
SOCIAL_NETWORK_DOMAINS: set[str] = {
    # International
    "facebook.com",
    "fb.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "reddit.com",
    "tiktok.com",
    "snapchat.com",
    "pinterest.com",
    "youtube.com",
    "twitch.tv",
    "tumblr.com",
    "flickr.com",
    "deviantart.com",
    "behance.net",
    "dribbble.com",
    "medium.com",
    "substack.com",
    "patreon.com",
    "soundcloud.com",
    "bandcamp.com",
    "last.fm",
    "spotify.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "keybase.io",
    "producthunt.com",
    "codepen.io",
    "replit.com",
    "stackoverflow.com",
    "quora.com",
    "about.me",
    "angel.co",
    "linktr.ee",
    "hackernews.com",
    "news.ycombinator.com",
    "mastodon.social",
    "threads.net",
    "bluesky.social",
    # Russian / CIS
    "vk.com",
    "ok.ru",
    "habr.com",
    "pikabu.ru",
    "livejournal.com",
    "drive2.ru",
    "yaplakal.com",
    "dtf.ru",
    "cyberforum.ru",
    "yandex.ru",
    "yandex.com",
    "mail.ru",
    "rambler.ru",
    # Messaging
    "t.me",
    "telegram.org",
    "telegram.me",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "whatsapp.com",
    "signal.org",
    "viber.com",
    "skype.com",
    "line.me",
    "wechat.com",
    "qq.com",
    "slack.com",
    "matrix.to",
    "element.io",
    # Gaming
    "steamcommunity.com",
    "steampowered.com",
    "epicgames.com",
    "origin.com",
    "ea.com",
    "xbox.com",
    "playstation.com",
    "battle.net",
    "ubisoft.com",
    "rockstargames.com",
    "chess.com",
    "lichess.org",
}

_SOCIAL_DOMAIN_PATTERNS = [
    re.compile(r"(^|\.)" + re.escape(d) + r"$", re.I) for d in SOCIAL_NETWORK_DOMAINS
]

# --- Precompiled config patterns ---
_SEARCH_RES = [re.compile(p, re.I) for p in SEARCH_URL_PATTERNS]
_ERROR_RES = [re.compile(p, re.I) for p in ERROR_PATTERNS]

# ============================================================================
# ОСНОВНЫЕ ВАЛИДАТОРЫ
# ============================================================================


def validate_email(email: str) -> bool:
    """Validate email address format."""
    if not isinstance(email, str):
        return False
    return bool(_EMAIL_RE.match(email))


def validate_phone(phone: str) -> bool:
    """Validate phone number (international format)."""
    if not isinstance(phone, str):
        return False
    cleaned = re.sub(r"[\s\-()]", "", phone)
    return bool(_PHONE_RE.match(cleaned))


def validate_ip(ip: str) -> bool:
    """Validate IPv4 or IPv6 address."""
    if not isinstance(ip, str):
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_ipv4(ip: str) -> bool:
    """Validate IPv4 address only."""
    if not isinstance(ip, str):
        return False
    try:
        addr = ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def validate_ipv6(ip: str) -> bool:
    """Validate IPv6 address only."""
    if not isinstance(ip, str):
        return False
    try:
        addr = ipaddress.IPv6Address(ip)
        return True
    except ValueError:
        return False


def validate_username(username: str, min_len: int = 3, max_len: int = 30) -> bool:
    """Validate generic username (alphanumeric + ._-)."""
    if not isinstance(username, str):
        return False
    return bool(_USERNAME_RE.match(username))


def validate_domain(domain: str) -> bool:
    """Validate domain name (e.g. example.com)."""
    if not isinstance(domain, str):
        return False
    return bool(_DOMAIN_RE.match(domain))


def validate_uuid(uuid_str: str, version: int | None = None) -> bool:
    """Validate UUID string. Optionally check version."""
    if not isinstance(uuid_str, str):
        return False
    try:
        if version:
            u = uuid.UUID(uuid_str, version=version)
        else:
            u = uuid.UUID(uuid_str)
        return str(u) == uuid_str
    except (ValueError, AttributeError):
        return False


def validate_uuid4(uuid_str: str) -> bool:
    """Validate UUID v4 specifically."""
    return validate_uuid(uuid_str, version=4)


def validate_hash(hash_str: str) -> Optional[str]:
    """Detect hash type. Returns 'md5', 'sha1', 'sha256', 'sha512' or None."""
    if not isinstance(hash_str, str):
        return None
    h = hash_str.strip()
    if _MD5_RE.match(h):
        return "md5"
    if _SHA1_RE.match(h):
        return "sha1"
    if _SHA256_RE.match(h):
        return "sha256"
    if _SHA512_RE.match(h):
        return "sha512"
    return None


def validate_url(url: str, require_http: bool = True) -> bool:
    """Validate URL format. Optionally require http/https scheme."""
    if not isinstance(url, str):
        return False
    try:
        result = urlparse(url)
        if require_http and result.scheme not in ("http", "https"):
            return False
        return bool(result.netloc) and bool(result.scheme)
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP is in a private/reserved range."""
    if not isinstance(ip, str):
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def is_blacklisted(url: str) -> bool:
    """Check if URL domain is in the blacklist."""
    if not isinstance(url, str):
        return False
    try:
        host = (urlparse(url).netloc or url).lower()
        host = host.split(":")[0]
    except ValueError:
        return False
    return any(
        host == bad.lower() or host.endswith("." + bad.lower())
        for bad in BLACKLIST_SITES
    )


def is_search_page(url: str) -> bool:
    """Check if URL matches search page patterns."""
    if not isinstance(url, str):
        return False
    return any(p.search(url) for p in _SEARCH_RES)


def is_error_page(html: str) -> bool:
    """Check if HTML contains error page patterns."""
    if not isinstance(html, str):
        return False
    text = html.lower()
    return any(p.search(text) for p in _ERROR_RES)


def is_social_network(url: str) -> bool:
    """Check if URL belongs to a known social network."""
    if not isinstance(url, str):
        return False
    try:
        host = (urlparse(url).netloc or url).lower()
        host = host.split(":")[0]
    except ValueError:
        return False
    return any(p.search(host) for p in _SOCIAL_DOMAIN_PATTERNS)


def is_valid_port(port: int) -> bool:
    """Check if port number is valid (1-65535)."""
    if not isinstance(port, int):
        return False
    return 1 <= port <= 65535


# ============================================================================
# DISCORD-СПЕЦИФИЧНЫЕ ВАЛИДАТОРЫ
# ============================================================================


def validate_discord_snowflake(snowflake: str) -> bool:
    """Validate Discord snowflake ID (17-20 digits)."""
    if not isinstance(snowflake, str):
        return False
    return bool(_DISCORD_SNOWFLAKE_RE.match(snowflake))


def validate_discord_token(token: str) -> bool:
    """Validate Discord bot/user token format."""
    if not isinstance(token, str):
        return False
    # Check for common patterns: MTEx..., NTEx..., OTE...
    return bool(_DISCORD_TOKEN_RE.match(token))


def validate_discord_invite(text: str) -> bool:
    """Check if text contains a Discord invite link."""
    if not isinstance(text, str):
        return False
    return bool(_DISCORD_INVITE_RE.search(text))


def extract_discord_invites(text: str) -> list[str]:
    """Extract all Discord invite codes from text."""
    if not isinstance(text, str):
        return []
    return list(set(_DISCORD_INVITE_RE.findall(text)))


def extract_discord_mentions(text: str) -> dict[str, list[str]]:
    """Extract Discord mentions from text.
    Returns dict with keys: 'users', 'channels', 'roles', 'emojis'
    """
    result: dict[str, list[str]] = {
        "users": [],
        "channels": [],
        "roles": [],
        "emojis": [],
    }
    if not isinstance(text, str):
        return result
    result["users"] = list(set(_DISCORD_USER_MENTION_RE.findall(text)))
    result["channels"] = list(set(_DISCORD_CHANNEL_MENTION_RE.findall(text)))
    result["roles"] = list(set(_DISCORD_ROLE_MENTION_RE.findall(text)))
    result["emojis"] = list(set(m[1] for m in _DISCORD_EMOJI_RE.findall(text)))
    return result


# ============================================================================
# TELEGRAM-СПЕЦИФИЧНЫЕ ВАЛИДАТОРЫ
# ============================================================================


def validate_telegram_token(token: str) -> bool:
    """Validate Telegram bot token format (bot father format)."""
    if not isinstance(token, str):
        return False
    return bool(_TELEGRAM_TOKEN_RE.match(token))


def validate_telegram_username(username: str) -> bool:
    """Validate Telegram username (without @)."""
    if not isinstance(username, str):
        return False
    if username.startswith("@"):
        username = username[1:]
    return bool(_TELEGRAM_USERNAME_RE.match(username))


def validate_telegram_chat_id(chat_id: str) -> bool:
    """Validate Telegram chat/group/channel ID."""
    if not isinstance(chat_id, str):
        return False
    return bool(_TELEGRAM_CHAT_ID_RE.match(chat_id))


# ============================================================================
# КРИПТО-ВАЛИДАТОРЫ
# ============================================================================


def validate_btc_address(address: str) -> bool:
    """Validate Bitcoin address (legacy P2PKH, P2SH, or bech32)."""
    if not isinstance(address, str):
        return False
    return bool(_BTC_ADDRESS_RE.match(address))


def validate_eth_address(address: str) -> bool:
    """Validate Ethereum address (0x + 40 hex chars)."""
    if not isinstance(address, str):
        return False
    return bool(_ETH_ADDRESS_RE.match(address))


def validate_trx_address(address: str) -> bool:
    """Validate TRON (TRC-20) address."""
    if not isinstance(address, str):
        return False
    return bool(_TRX_ADDRESS_RE.match(address))


def validate_sol_address(address: str) -> bool:
    """Validate Solana address."""
    if not isinstance(address, str):
        return False
    return bool(_SOL_ADDRESS_RE.match(address))


def validate_crypto_address(address: str) -> Optional[str]:
    """Auto-detect crypto address type.
    Returns 'btc', 'eth', 'trx', 'sol' or None.
    """
    if not isinstance(address, str):
        return None
    if _BTC_ADDRESS_RE.match(address):
        return "btc"
    if _ETH_ADDRESS_RE.match(address):
        return "eth"
    if _TRX_ADDRESS_RE.match(address):
        return "trx"
    if _SOL_ADDRESS_RE.match(address):
        return "sol"
    return None


# ============================================================================
# NETWORK / SYSTEM ВАЛИДАТОРЫ
# ============================================================================


def validate_mac_address(mac: str) -> bool:
    """Validate MAC address (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)."""
    if not isinstance(mac, str):
        return False
    return bool(_MAC_ADDRESS_RE.match(mac))


def validate_ssh_key(key: str) -> bool:
    """Validate SSH public key format (basic check)."""
    if not isinstance(key, str):
        return False
    return bool(_SSH_KEY_RE.match(key.strip()))


def validate_port_range(port_range: str) -> bool:
    """Validate port range string like '80', '80,443', '1-1024'."""
    if not isinstance(port_range, str):
        return False
    parts = port_range.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            try:
                low, high = map(int, part.split("-", 1))
                if not (1 <= low <= high <= 65535):
                    return False
            except ValueError:
                return False
        else:
            try:
                p = int(part)
                if not (1 <= p <= 65535):
                    return False
            except ValueError:
                return False
    return True


# ============================================================================
# API-KEY / TOKEN ВАЛИДАТОРЫ
# ============================================================================


def validate_github_token(token: str) -> bool:
    """Validate GitHub personal access token format."""
    if not isinstance(token, str):
        return False
    return bool(_GITHUB_TOKEN_RE.match(token))


def validate_aws_key(key: str) -> bool:
    """Validate AWS Access Key ID format."""
    if not isinstance(key, str):
        return False
    return bool(_AWS_KEY_RE.match(key))


def validate_aws_secret(secret: str) -> bool:
    """Validate AWS Secret Access Key format."""
    if not isinstance(secret, str):
        return False
    return bool(_AWS_SECRET_RE.match(secret))


def validate_slack_token(token: str) -> bool:
    """Validate Slack API token format."""
    if not isinstance(token, str):
        return False
    return bool(_SLACK_TOKEN_RE.match(token))


def validate_stripe_key(key: str) -> bool:
    """Validate Stripe API key format."""
    if not isinstance(key, str):
        return False
    return bool(_STRIPE_KEY_RE.match(key))


def validate_api_key(key: str) -> Optional[str]:
    """Auto-detect API key type.
    Returns 'discord_bot', 'telegram_bot', 'github', 'aws_key', 'slack', 'stripe' or None.
    """
    if not isinstance(key, str):
        return None
    if _DISCORD_TOKEN_RE.match(key):
        return "discord_bot"
    if _TELEGRAM_TOKEN_RE.match(key):
        return "telegram_bot"
    if _GITHUB_TOKEN_RE.match(key):
        return "github"
    if _AWS_KEY_RE.match(key):
        return "aws_key"
    if _SLACK_TOKEN_RE.match(key):
        return "slack"
    if _STRIPE_KEY_RE.match(key):
        return "stripe"
    return None


# ============================================================================
# SOCIAL MEDIA USERNAME ВАЛИДАТОРЫ
# ============================================================================


def validate_twitter_handle(handle: str) -> bool:
    """Validate Twitter/X handle (1-15 chars, alphanumeric + underscore)."""
    if not isinstance(handle, str):
        return False
    handle = handle.lstrip("@")
    return bool(_TWITTER_HANDLE_RE.match(handle))


def validate_instagram_username(username: str) -> bool:
    """Validate Instagram username format."""
    if not isinstance(username, str):
        return False
    return bool(_INSTAGRAM_USERNAME_RE.match(username))


# ============================================================================
# URL-АНАЛИЗ
# ============================================================================


def parse_url(url: str) -> dict[str, Any]:
    """Parse URL into components.
    Returns dict with: scheme, host, port, path, params, query, fragment, query_params
    """
    result: dict[str, Any] = {
        "scheme": "",
        "host": "",
        "port": None,
        "path": "",
        "params": "",
        "query": "",
        "fragment": "",
        "query_params": {},
        "valid": False,
    }
    if not isinstance(url, str) or not url.strip():
        return result

    try:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0] if parsed.netloc else ""
        port_str = parsed.netloc.split(":")[1] if ":" in parsed.netloc else None
        port = int(port_str) if port_str and port_str.isdigit() else None

        result.update(
            {
                "scheme": parsed.scheme,
                "host": host,
                "port": port,
                "path": parsed.path,
                "params": parsed.params,
                "query": parsed.query,
                "fragment": parsed.fragment,
                "query_params": {
                    k: v[0] if len(v) == 1 else v
                    for k, v in parse_qs(parsed.query).items()
                },
                "valid": bool(host) and bool(parsed.scheme),
            }
        )
    except Exception:
        pass

    return result


def get_mime_type(filename: str) -> str:
    """Guess MIME type from file extension."""
    if not isinstance(filename, str):
        return "application/octet-stream"
    ext = os.path.splitext(filename.split("?")[0].split("#")[0])[1].lower()
    return _MIME_EXTENSIONS.get(ext, "application/octet-stream")


# ============================================================================
# ЭКСТРАКТОРЫ
# ============================================================================


def extract_ips(text: str) -> list[str]:
    """Extract all valid IPv4 and IPv6 addresses from text."""
    if not isinstance(text, str):
        return []
    ips: list[str] = []
    seen: set[str] = set()

    for match in _IPV4_RE.finditer(text):
        candidate = match.group()
        try:
            ipaddress.IPv4Address(candidate)
            if candidate not in seen:
                seen.add(candidate)
                ips.append(candidate)
        except ValueError:
            pass

    for match in _IPV6_RE.finditer(text):
        candidate = match.group()
        try:
            ipaddress.IPv6Address(candidate)
            if candidate not in seen:
                seen.add(candidate)
                ips.append(candidate)
        except ValueError:
            pass

    return ips


def extract_emails(text: str) -> list[str]:
    """Extract all email addresses from text."""
    if not isinstance(text, str):
        return []
    return list(set(_EMAIL_EXTRACT_RE.findall(text)))


def extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from text."""
    if not isinstance(text, str):
        return []
    return list(set(_URL_EXTRACT_RE.findall(text)))


def extract_domains(text: str) -> list[str]:
    """Extract domain names from text (not from URLs, raw)."""
    if not isinstance(text, str):
        return []
    # Find all potential domain-like patterns
    potential = re.findall(
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}", text
    )
    return list(set(d.lower() for d in potential if validate_domain(d)))


def extract_phone_numbers(text: str) -> list[str]:
    """Extract phone numbers from text."""
    if not isinstance(text, str):
        return []
    # Find raw phone-like strings and validate
    potential = re.findall(r"\+?[\d\s\-()]{7,}", text)
    valid = []
    seen: set[str] = set()
    for p in potential:
        cleaned = re.sub(r"[\s\-()]", "", p)
        if _PHONE_RE.match(cleaned) and cleaned not in seen:
            seen.add(cleaned)
            valid.append(cleaned)
    return valid


def extract_mac_addresses(text: str) -> list[str]:
    """Extract MAC addresses from text."""
    if not isinstance(text, str):
        return []
    return list(set(_MAC_ADDRESS_RE.findall(text)))


def extract_crypto_addresses(text: str) -> dict[str, list[str]]:
    """Extract cryptocurrency addresses from text.
    Returns dict with keys: 'btc', 'eth', 'trx', 'sol'
    """
    result: dict[str, list[str]] = {"btc": [], "eth": [], "trx": [], "sol": []}
    if not isinstance(text, str):
        return result

    # Split by whitespace to check each token
    for token in re.split(r'[\s,;:()\[\]{}"\']+', text):
        token = token.strip()
        if not token:
            continue
        detected = validate_crypto_address(token)
        if detected:
            result[detected].append(token)

    return result


def extract_query_params(url: str) -> dict[str, str | list[str]]:
    """Extract query parameters from URL as dict."""
    return parse_url(url).get("query_params", {})


# ============================================================================
# НОРМАЛИЗАЦИЯ
# ============================================================================


def normalize_phone(phone: str) -> str:
    """Normalize phone number to international format (+7...)."""
    if not isinstance(phone, str):
        return ""
    cleaned = re.sub(r"[^\d+]", "", phone)
    if not cleaned:
        return ""
    # Russian numbers starting with 8
    if cleaned.startswith("8") and len(cleaned) == 11:
        cleaned = "+7" + cleaned[1:]
    elif not cleaned.startswith("+"):
        cleaned = "+" + cleaned
    if _PHONE_RE.match(cleaned):
        return cleaned
    return ""


def sanitize_input(value: str) -> str:
    """Remove control characters and strip whitespace."""
    if not isinstance(value, str):
        return ""
    return _CONTROL_CHARS_RE.sub("", value.strip())


def strip_html_tags(html: str) -> str:
    """Remove HTML tags, keep text content."""
    if not isinstance(html, str):
        return ""
    clean = re.sub(r"<[^>]+>", " ", html)
    clean = re.sub(r"\s+", " ", clean)
    return clean.strip()


# ============================================================================
# КЛАСС-ОБЁРТКА ДЛЯ УДОБСТВА
# ============================================================================


class Validator:
    """Convenience wrapper with static methods for all validation functions."""

    # --- Basic ---
    @staticmethod
    def email(email: str) -> bool:
        return validate_email(email)

    @staticmethod
    def phone(phone: str) -> bool:
        return validate_phone(phone)

    @staticmethod
    def ip(ip: str) -> bool:
        return validate_ip(ip)

    @staticmethod
    def ipv4(ip: str) -> bool:
        return validate_ipv4(ip)

    @staticmethod
    def ipv6(ip: str) -> bool:
        return validate_ipv6(ip)

    @staticmethod
    def username(username: str, min_len: int = 3, max_len: int = 30) -> bool:
        return validate_username(username, min_len, max_len)

    @staticmethod
    def domain(domain: str) -> bool:
        return validate_domain(domain)

    @staticmethod
    def uuid(uuid_str: str, version: int | None = None) -> bool:
        return validate_uuid(uuid_str, version)

    @staticmethod
    def uuid4(uuid_str: str) -> bool:
        return validate_uuid4(uuid_str)

    @staticmethod
    def hash(hash_str: str) -> Optional[str]:
        return validate_hash(hash_str)

    @staticmethod
    def url(url: str, require_http: bool = True) -> bool:
        return validate_url(url, require_http)

    @staticmethod
    def port(port: int) -> bool:
        return is_valid_port(port)

    @staticmethod
    def port_range(port_range: str) -> bool:
        return validate_port_range(port_range)

    @staticmethod
    def mac(mac: str) -> bool:
        return validate_mac_address(mac)

    # --- Location/Filter ---
    @staticmethod
    def private_ip(ip: str) -> bool:
        return is_private_ip(ip)

    @staticmethod
    def blacklisted(url: str) -> bool:
        return is_blacklisted(url)

    @staticmethod
    def search_page(url: str) -> bool:
        return is_search_page(url)

    @staticmethod
    def error_page(html: str) -> bool:
        return is_error_page(html)

    @staticmethod
    def social_network(url: str) -> bool:
        return is_social_network(url)

    # --- Discord ---
    @staticmethod
    def discord_snowflake(snowflake: str) -> bool:
        return validate_discord_snowflake(snowflake)

    @staticmethod
    def discord_token(token: str) -> bool:
        return validate_discord_token(token)

    @staticmethod
    def discord_invite(text: str) -> bool:
        return validate_discord_invite(text)

    # --- Telegram ---
    @staticmethod
    def telegram_token(token: str) -> bool:
        return validate_telegram_token(token)

    @staticmethod
    def telegram_username(username: str) -> bool:
        return validate_telegram_username(username)

    @staticmethod
    def telegram_chat_id(chat_id: str) -> bool:
        return validate_telegram_chat_id(chat_id)

    # --- Crypto ---
    @staticmethod
    def btc(address: str) -> bool:
        return validate_btc_address(address)

    @staticmethod
    def eth(address: str) -> bool:
        return validate_eth_address(address)

    @staticmethod
    def trx(address: str) -> bool:
        return validate_trx_address(address)

    @staticmethod
    def sol(address: str) -> bool:
        return validate_sol_address(address)

    @staticmethod
    def crypto(address: str) -> Optional[str]:
        return validate_crypto_address(address)

    # --- API Keys ---
    @staticmethod
    def github_token(token: str) -> bool:
        return validate_github_token(token)

    @staticmethod
    def aws_key(key: str) -> bool:
        return validate_aws_key(key)

    @staticmethod
    def aws_secret(secret: str) -> bool:
        return validate_aws_secret(secret)

    @staticmethod
    def slack_token(token: str) -> bool:
        return validate_slack_token(token)

    @staticmethod
    def stripe_key(key: str) -> bool:
        return validate_stripe_key(key)

    @staticmethod
    def api_key(key: str) -> Optional[str]:
        return validate_api_key(key)

    # --- Social Media ---
    @staticmethod
    def twitter_handle(handle: str) -> bool:
        return validate_twitter_handle(handle)

    @staticmethod
    def instagram_username(username: str) -> bool:
        return validate_instagram_username(username)

    # --- Extractors ---
    @staticmethod
    def extract_ips(text: str) -> list[str]:
        return extract_ips(text)

    @staticmethod
    def extract_emails(text: str) -> list[str]:
        return extract_emails(text)

    @staticmethod
    def extract_urls(text: str) -> list[str]:
        return extract_urls(text)

    @staticmethod
    def extract_domains(text: str) -> list[str]:
        return extract_domains(text)

    @staticmethod
    def extract_phones(text: str) -> list[str]:
        return extract_phone_numbers(text)

    @staticmethod
    def extract_macs(text: str) -> list[str]:
        return extract_mac_addresses(text)

    @staticmethod
    def extract_crypto(text: str) -> dict[str, list[str]]:
        return extract_crypto_addresses(text)

    @staticmethod
    def extract_query_params(url: str) -> dict[str, str | list[str]]:
        return extract_query_params(url)

    @staticmethod
    def extract_discord_invites(text: str) -> list[str]:
        return extract_discord_invites(text)

    @staticmethod
    def extract_discord_mentions(text: str) -> dict[str, list[str]]:
        return extract_discord_mentions(text)

    # --- Normalizers ---
    @staticmethod
    def normalize_phone(phone: str) -> str:
        return normalize_phone(phone)

    @staticmethod
    def sanitize(value: str) -> str:
        return sanitize_input(value)

    @staticmethod
    def strip_html(html: str) -> str:
        return strip_html_tags(html)

    @staticmethod
    def mime_type(filename: str) -> str:
        return get_mime_type(filename)

    @staticmethod
    def parse_url(url: str) -> dict[str, Any]:
        return parse_url(url)


# ============================================================================
# re-export for backward compatibility
# ============================================================================

__all__ = [
    # Validators
    "validate_email",
    "validate_phone",
    "validate_ip",
    "validate_ipv4",
    "validate_ipv6",
    "validate_username",
    "validate_domain",
    "validate_uuid",
    "validate_uuid4",
    "validate_hash",
    "validate_url",
    "validate_port_range",
    "validate_mac_address",
    "validate_ssh_key",
    # Discord
    "validate_discord_snowflake",
    "validate_discord_token",
    "validate_discord_invite",
    "extract_discord_invites",
    "extract_discord_mentions",
    # Telegram
    "validate_telegram_token",
    "validate_telegram_username",
    "validate_telegram_chat_id",
    # Crypto
    "validate_btc_address",
    "validate_eth_address",
    "validate_trx_address",
    "validate_sol_address",
    "validate_crypto_address",
    # API Keys
    "validate_github_token",
    "validate_aws_key",
    "validate_aws_secret",
    "validate_slack_token",
    "validate_stripe_key",
    "validate_api_key",
    # Social
    "validate_twitter_handle",
    "validate_instagram_username",
    # Filters
    "is_private_ip",
    "is_blacklisted",
    "is_search_page",
    "is_error_page",
    "is_social_network",
    "is_valid_port",
    # Extractors
    "extract_ips",
    "extract_emails",
    "extract_urls",
    "extract_domains",
    "extract_phone_numbers",
    "extract_mac_addresses",
    "extract_crypto_addresses",
    "extract_query_params",
    # Normalizers
    "normalize_phone",
    "sanitize_input",
    "strip_html_tags",
    "get_mime_type",
    "parse_url",
    # Class
    "Validator",
]
