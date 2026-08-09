"""Тесты чистой логики telegram-модуля (без сети и Telethon)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers import telegram as tg


class TestClassify:
    def test_plain_username(self):
        t = tg._classify("@durov")
        assert t.kind == "username" and t.value == "durov"

    def test_url_username(self):
        t = tg._classify("https://t.me/durov")
        assert t.kind == "username" and t.value == "durov"

    def test_url_with_query(self):
        t = tg._classify("t.me/durov?before=100")
        assert t.kind == "username" and t.value == "durov"

    def test_phone(self):
        t = tg._classify("+1 (234) 567-8901")
        assert t.kind == "phone" and t.value == "+12345678901"

    def test_phone_without_plus(self):
        t = tg._classify("12345678901")
        assert t.kind == "phone" and t.value == "+12345678901"

    def test_invite_joinchat(self):
        t = tg._classify("https://t.me/joinchat/AAAAAE_xyz")
        assert t.kind == "invite" and t.value == "AAAAAE_xyz"

    def test_invite_plus(self):
        t = tg._classify("t.me/+AbCdEf_hyphen-code")
        assert t.kind == "invite" and t.value == "AbCdEf_hyphen-code"


class TestChannelGaps:
    def test_gap_math(self):
        # посты 10..20, но видно только 9 из 11 -> 2 разрыва
        act = tg.ChannelActivity(first_post_id=10, last_post_id=20, seen_posts=9)
        gaps = act.last_post_id - act.first_post_id + 1 - act.seen_posts
        assert gaps == 2
