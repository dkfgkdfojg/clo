"""Тесты нового Discord API-тира: декод public_flags, аватар, регэксп инвайта."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers import discord as d


class TestDecodeFlags:
    def test_empty(self):
        assert d._decode_flags(0) == []

    def test_active_developer(self):
        assert d._decode_flags(1 << 22) == ["Active Developer"]

    def test_multiple(self):
        flags = (1 << 0) | (1 << 9) | (1 << 16)  # Staff + Early Supporter + Verified Bot
        got = d._decode_flags(flags)
        assert "Discord Staff" in got
        assert "Early Supporter" in got
        assert "Verified Bot" in got
        assert len(got) == 3


class TestAvatarUrl:
    def test_none(self):
        assert d._avatar_url("123", None) == ""

    def test_static(self):
        url = d._avatar_url("123", "abcdef")
        assert url.endswith(".png?size=1024") and "/avatars/123/abcdef" in url

    def test_animated(self):
        url = d._avatar_url("123", "a_animated")
        assert ".gif" in url


class TestInviteRegex:
    def test_discord_gg(self):
        m = d._INVITE_RE.search("join https://discord.gg/AbC123 now")
        assert m and m.group(1) == "AbC123"

    def test_full_invite_url(self):
        m = d._INVITE_RE.search("https://discord.com/invite/python")
        assert m and m.group(1) == "python"

    def test_no_match(self):
        assert d._INVITE_RE.search("just some text") is None
