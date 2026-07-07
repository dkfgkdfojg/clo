"""Регрессионные тесты для core.validator.

Покрывают два исправленных бага:
  * validate_ssh_key — раньше регексп был сломан (класс символов не в [...]),
    функция всегда возвращала False даже для валидных ключей.
  * validate_username — раньше игнорировал параметры min_len / max_len.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from core import validator as v


# --------------------------------------------------------------------------
# FIX 1: validate_ssh_key
# --------------------------------------------------------------------------
class TestSSHKey:
    def test_valid_rsa(self):
        key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD1234567890abcdefg"
        assert v.validate_ssh_key(key) is True

    def test_valid_ed25519_with_comment(self):
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcDEF user@host"
        assert v.validate_ssh_key(key) is True

    def test_valid_ecdsa(self):
        key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY="
        assert v.validate_ssh_key(key) is True

    @pytest.mark.parametrize("bad", ["", "not a key", "ssh-rsa", "rsa AAAA"])
    def test_invalid(self, bad):
        assert v.validate_ssh_key(bad) is False


# --------------------------------------------------------------------------
# FIX 2: validate_username honours min_len / max_len
# --------------------------------------------------------------------------
class TestUsername:
    def test_default_bounds(self):
        assert v.validate_username("ab") is False          # < 3
        assert v.validate_username("abc") is True
        assert v.validate_username("a" * 30) is True
        assert v.validate_username("a" * 31) is False       # > 30

    def test_custom_min_len(self):
        assert v.validate_username("ab", min_len=1) is True

    def test_custom_max_len(self):
        assert v.validate_username("a" * 40, max_len=50) is True
        assert v.validate_username("a" * 40) is False        # default max still 30

    def test_bad_chars(self):
        assert v.validate_username("bad name", min_len=1) is False
        assert v.validate_username("john_doe") is True

    def test_wrapper_matches(self):
        assert v.Validator.username("hi", min_len=2) is True


# --------------------------------------------------------------------------
# Smoke-регрессии по остальным валидаторам
# --------------------------------------------------------------------------
class TestSmoke:
    def test_email(self):
        assert v.validate_email("a@b.com") is True
        assert v.validate_email("nope") is False

    def test_ip(self):
        assert v.validate_ip("8.8.8.8") is True
        assert v.validate_ip("999.1.1.1") is False

    def test_crypto_detect(self):
        assert v.validate_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "btc"
        assert v.validate_crypto_address("0x" + "a" * 40) == "eth"

    def test_extract_phones(self):
        assert v.extract_phone_numbers("call +12025551234 now")

    def test_non_str_inputs(self):
        assert v.validate_email(None) is False
        assert v.validate_username(123) is False
        assert v.validate_ssh_key(None) is False
