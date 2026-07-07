# core/http.py
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .utils import logger


def get_headers(mobile=False):
    if mobile:
        return {
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
        }
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }


def _redact(url: str) -> str:
    """Strip the query string so API keys/tokens don't leak into osint.log."""
    return url.split("?", 1)[0]


def get_session(mobile=False, retries=2, backoff=0.5):
    """Сессия с ретраями ТОЛЬКО по HTTP-статусам (429/5xx).

    Транспортные исключения (Timeout/ConnectionError) обрабатывает safe_get —
    так два слоя ретраев не компаундятся (раньше адаптер и safe_get повторяли
    одну и ту же сетевую ошибку, давая до ~9-12 запросов на упавший хост).
    """
    session = requests.Session()
    session.headers.update(get_headers(mobile))
    retry = Retry(
        total=None,          # granular-лимиты ниже применяются независимо
        connect=0,           # транспортные ретраи — за safe_get
        read=0,
        redirect=0,
        status=retries,      # повторяем только по статус-кодам
        status_forcelist=[429, 500, 502, 503, 504],
        backoff_factor=backoff,
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def safe_get(session, url, timeout=12, retries=2, **kwargs):
    """
    Выполняет GET с повторными попытками при транспортных ошибках сети.
    Перехватывает: Timeout, ConnectionError, TooManyRedirects.
    (HTTPError не ловим: session.get без raise_for_status() его не бросает —
    не-2xx статусы возвращаются как есть, вызывающий код проверяет status_code.)
    """
    for attempt in range(retries + 1):
        try:
            return session.get(url, timeout=timeout, **kwargs)
        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.TooManyRedirects,
        ) as e:
            if attempt < retries:
                sleep_time = 1.2 * (attempt + 1)
                time.sleep(sleep_time)
                logger.debug("Retry %d/%d for %s: %s", attempt + 1, retries, _redact(url), e)
            else:
                logger.error("Failed to fetch %s: %s", _redact(url), e)
                raise
