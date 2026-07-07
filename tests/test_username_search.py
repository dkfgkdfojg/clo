"""Регрессионные тесты для analyzers.username (логика поиска).

Покрывают рефакторинг _check_single_url (убрано тройное дублирование ветвей)
и корректность _is_error_page на прекомпилированных паттернах.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers import username as u


class _Resp:
    def __init__(self, code, url, text=""):
        self.status_code = code
        self.url = url
        self.text = text


class _MockSession:
    """Отдаёт заданный HEAD-ответ и один и тот же body на GET."""

    def __init__(self, head_code, final_url, body):
        self._head_code = head_code
        self._final_url = final_url
        self._body = body

    def head(self, url, timeout=None, allow_redirects=True):
        return _Resp(self._head_code, self._final_url)

    def get(self, url, timeout=None, **kw):
        return _Resp(200, url, self._body)


USER = "johndoe"
PROFILE = (
    "<html><title>johndoe profile</title><body>"
    + "x" * 300
    + " johndoe posts here</body></html>"
)
ERRPAGE = (
    "<html><title>Error 404</title><body>user not found "
    + "x" * 300
    + "</body></html>"
)


class TestCheckSingleUrl:
    def test_head_non_200_returns_none(self):
        s = _MockSession(404, "https://site.com/johndoe", "")
        assert u._check_single_url("s", "https://site.com/johndoe", USER, s) is None

    def test_200_name_present_found(self):
        s = _MockSession(200, "https://site.com/johndoe", PROFILE)
        r = u._check_single_url("s", "https://site.com/johndoe", USER, s)
        assert r is not None and r.url == "https://site.com/johndoe"

    def test_200_name_absent_returns_none(self):
        s = _MockSession(200, "https://site.com/johndoe", "<html>" + "y" * 400 + "</html>")
        assert u._check_single_url("s", "https://site.com/johndoe", USER, s) is None

    def test_200_error_page_returns_none(self):
        s = _MockSession(200, "https://site.com/johndoe", ERRPAGE)
        assert u._check_single_url("s", "https://site.com/johndoe", USER, s) is None

    def test_blacklisted_skipped(self):
        bad = list(u.BLACKLIST_SITES)[0]
        s = _MockSession(200, f"https://{bad}/johndoe", PROFILE)
        assert u._check_single_url("s", f"https://{bad}/johndoe", USER, s) is None

    def test_redirect_final_url_used(self):
        s = _MockSession(200, "https://site.com/profile/johndoe", PROFILE)
        r = u._check_single_url("s", "https://site.com/u/johndoe", USER, s)
        assert r is not None and r.url == "https://site.com/profile/johndoe"


class TestIsErrorPage:
    def test_short_page_is_error(self):
        assert u._is_error_page("<html>tiny</html>", "https://x.com/u", "u") is True

    def test_not_found_text(self):
        html = "<html><body>" + "x" * 300 + " user not found</body></html>"
        assert u._is_error_page(html, "https://x.com/u", "u") is True

    def test_valid_profile_not_error(self):
        assert u._is_error_page(PROFILE, "https://x.com/johndoe", USER) is False

    def test_search_url_is_error(self):
        # SEARCH_URL_PATTERNS помечает поисковые страницы как не-профиль
        html = "<html><body>" + "x" * 300 + " johndoe</body></html>"
        assert u._is_error_page(html, "https://x.com/search?q=johndoe", USER) is True
