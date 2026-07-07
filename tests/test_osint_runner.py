"""Регрессионные тесты для core.osint_runner (оркестратор CLI-инструментов).

Покрывают исправленные баги:
  * _parse_sherlock / _parse_maigret — fallback восстанавливает реальные имена
    сайтов из текстового вывода "[+] Site: url" (раньше Sherlock схлопывал всё
    в 'sherlock_unknown', Maigret вообще возвращал 0).
  * _parse_holehe — только положительные "[+]" строки (раньше re.search вне
    ветки добавлял мусор на каждой строке).
  * _parse_nexfil — фильтр по маркеру находки (раньше баннерные URL считались
    аккаунтами).
  * _parse_socialscan — "unavailable" = занято = найдено (раньше терялось).
  * check_tool_installed — EXTENDED_TOOLS (check_installed=None) теперь
    определяются (раньше всегда считались неустановленными).
  * ToolConfig.email_only — Holehe помечен как email-only.
  * register_user_script / run_user_script — подстановка {username} через $1.
  * импорт модуля не имеет побочных эффектов (нет mkdir на уровне модуля).
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import osint_runner as r
from core.osint_runner import ToolConfig, _parse_generic_json, check_tool_installed


class TestSherlockParser:
    def test_json_mode(self):
        data = '{"GitHub": {"status": "Claimed", "url": "https://github.com/john"}}'
        res = r._parse_sherlock(data, "john")
        assert len(res) == 1 and res[0].site == "GitHub"

    def test_text_fallback_recovers_site_names(self):
        text = "[+] GitHub: https://github.com/john\n[+] Reddit: https://reddit.com/user/john"
        res = r._parse_sherlock(text, "john")
        assert {a.site for a in res} == {"GitHub", "Reddit"}
        assert all(a.site != "sherlock_unknown" for a in res)


class TestMaigretParser:
    def test_text_fallback_nonzero(self):
        text = "[+] VK: https://vk.com/john\n[+] Habr: https://habr.com/users/john"
        res = r._parse_maigret(text, "john")
        assert len(res) == 2
        assert {a.site for a in res} == {"VK", "Habr"}


class TestHoleheParser:
    def test_only_positive_lines(self):
        out = (
            "Holehe https://github.com/megadose/holehe\n"
            "[+] twitter.com\n"
            "[-] instagram.com\n"
            "[x] rate limited example.com\n"
        )
        res = r._parse_holehe(out, "a@b.com")
        assert {a.site for a in res} == {"twitter.com"}

    def test_empty_when_no_hits(self):
        assert r._parse_holehe("[-] a.com\n[-] b.com", "x@y.com") == []


class TestNexfilParser:
    def test_banner_url_ignored(self):
        out = (
            "NEXFIL by thewhiteh4t https://github.com/thewhiteh4t/nexfil\n"
            "[+] https://github.com/john\n"
            "checking sites...\n"
        )
        res = r._parse_nexfil(out, "john")
        assert {a.url for a in res} == {"https://github.com/john"}


class TestSocialscanParser:
    def test_unavailable_is_hit(self):
        out = "Instagram: Unavailable (taken)\nTwitter: Available\nGitHub: Unavailable"
        res = r._parse_socialscan(out, "john")
        assert {a.site for a in res} == {"Instagram", "GitHub"}

    def test_available_not_hit(self):
        assert r._parse_socialscan("Twitter: Available", "john") == []


class TestCheckToolInstalled:
    def test_explicit_binary_probe(self):
        # 'python3' точно есть в PATH
        t = ToolConfig("T", ["python3", "{username}"], _parse_generic_json,
                       check_installed="python3")
        assert check_tool_installed(t) is True

    def test_module_probe_existing(self):
        # python3 -m json.tool -> модуль json существует
        t = ToolConfig("T", ["python3", "-m", "json", "{username}"], _parse_generic_json)
        assert check_tool_installed(t) is True

    def test_module_probe_missing(self):
        t = ToolConfig("T", ["python3", "-m", "no_such_mod_xyz", "{username}"],
                       _parse_generic_json)
        assert check_tool_installed(t) is False  # не 'python3 есть -> True'

    def test_missing_binary(self):
        t = ToolConfig("T", ["definitely_not_a_real_binary_xyz"], _parse_generic_json)
        assert check_tool_installed(t) is False


class TestEmailOnly:
    def test_holehe_marked_email_only(self):
        holehe = [t for t in r.TOOLS if t.name == "Holehe"][0]
        assert holehe.email_only is True

    def test_other_tools_not_email_only(self):
        sherlock = [t for t in r.TOOLS if t.name == "Sherlock"][0]
        assert sherlock.email_only is False


class TestUserScript:
    def test_substitution_via_argv(self, tmp_path, monkeypatch):
        monkeypatch.setattr(r, "USER_SCRIPTS_DIR", tmp_path)
        p = r.register_user_script(
            "echotest",
            'printf \'[{"url":"https://x.com/%s","site":"x"}]\' {username}',
        )
        body = p.read_text()
        assert '"$1"' in body
        res = r.run_user_script("echotest", "john")
        assert any("john" in a.url for a in res)

    def test_mkdir_is_lazy(self, tmp_path, monkeypatch):
        # Директория создаётся только при регистрации, не при импорте
        target = tmp_path / "nested" / "scripts"
        monkeypatch.setattr(r, "USER_SCRIPTS_DIR", target)
        assert not target.exists()
        r.register_user_script("x", "echo {username}")
        assert target.exists()


class TestDeduplication:
    def test_dedup_by_url(self):
        from core.osint_runner import FoundAccount, _deduplicate_accounts
        accs = [
            FoundAccount("A", "https://x.com/j", "j", "s1"),
            FoundAccount("B", "https://x.com/j/", "j", "s2"),  # тот же URL (trailing /)
            FoundAccount("C", "https://y.com/j", "j", "s1"),
        ]
        res = _deduplicate_accounts(accs)
        assert len(res) == 2
