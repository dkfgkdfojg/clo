"""Тесты логики корреляции (классификация + извлечение сущностей), без сети."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers import investigate as inv
from core import report


class TestClassify:
    def test_email(self):
        assert inv._classify("john@example.com") == "email"

    def test_ip(self):
        assert inv._classify("8.8.8.8") == "ip"

    def test_discord_id(self):
        assert inv._classify("123456789012345678") == "discord"

    def test_phone(self):
        assert inv._classify("+79261234567") == "phone"

    def test_domain(self):
        assert inv._classify("example.com") == "domain"

    def test_github_url(self):
        assert inv._classify("github.com/torvalds") == "github"

    def test_username(self):
        assert inv._classify("cooldude") == "username"


class TestExtract:
    def _report_with(self, *fields):
        rep = report.Report("GitHub", "torvalds")
        rep.section("Профиль")
        for label, value in fields:
            rep.field(label, value)
        return rep

    def test_pulls_email_and_domain(self):
        rep = self._report_with(("Email", "linus@kernel.org"))
        ents = inv._extract(rep, "torvalds")
        kinds = {(e.kind, e.value) for e in ents}
        assert ("email", "linus@kernel.org") in kinds
        assert ("domain", "kernel.org") in kinds

    def test_skips_free_mail_domain(self):
        rep = self._report_with(("Email", "someone@gmail.com"))
        ents = inv._extract(rep, "x")
        assert ("domain", "gmail.com") not in {(e.kind, e.value) for e in ents}
        assert ("email", "someone@gmail.com") in {(e.kind, e.value) for e in ents}

    def test_github_and_telegram_from_urls(self):
        rep = self._report_with(
            ("Repo", "https://github.com/octocat"),
            ("TG", "https://t.me/durov"),
        )
        kinds = {(e.kind, e.value) for e in inv._extract(rep, "x")}
        assert ("github", "octocat") in kinds
        assert ("telegram", "durov") in kinds

    def test_skips_self(self):
        rep = self._report_with(("dup", "torvalds"))
        # self_value исключается только для сущностей того же написания
        ents = inv._extract(rep, "octocat")
        assert all(e.value != "octocat" for e in ents)

    def test_ignores_reserved_github(self):
        rep = self._report_with(("link", "https://github.com/features"))
        assert not any(e.kind == "github" for e in inv._extract(rep, "x"))
