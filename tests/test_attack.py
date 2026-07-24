# SPDX-License-Identifier: Apache-2.0
"""Tests for attack module helpers."""

from __future__ import annotations

from credwolf.attack import (
    _detect_kerberos_key,
    _hash_display,
    _parse_hash_line,
    _parse_hash_lines,
    _validate_hex_key,
)
from credwolf.log import Logger
from credwolf.models import AES128_KEY_HEX_LEN, AES256_KEY_HEX_LEN, RC4_KEY_HEX_LEN, EncryptionType


class TestParseHashLine:
    def test_bare_nt_hash(self) -> None:
        result = _parse_hash_line("aabbccdd11223344aabbccdd11223344")
        assert result == ("", "aabbccdd11223344aabbccdd11223344")

    def test_lm_nt_pair(self) -> None:
        lm = "aabbccdd11223344aabbccdd11223344"
        nt = "11223344aabbccdd11223344aabbccdd"
        result = _parse_hash_line(f"{lm}:{nt}")
        assert result == (lm, nt)

    def test_uppercase_normalized(self) -> None:
        result = _parse_hash_line("AABBCCDD11223344AABBCCDD11223344")
        assert result is not None
        assert result[1] == "aabbccdd11223344aabbccdd11223344"

    def test_strips_whitespace(self) -> None:
        result = _parse_hash_line("  aabbccdd11223344aabbccdd11223344  ")
        assert result is not None

    def test_invalid_short(self) -> None:
        assert _parse_hash_line("aabbccdd") is None

    def test_invalid_chars(self) -> None:
        assert _parse_hash_line("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") is None

    def test_invalid_lm_nt_bad_lm(self) -> None:
        nt = "aabbccdd11223344aabbccdd11223344"
        assert _parse_hash_line(f"tooshort:{nt}") is None

    def test_empty_string(self) -> None:
        assert _parse_hash_line("") is None

    def test_only_whitespace(self) -> None:
        assert _parse_hash_line("   ") is None

    def test_colon_only(self) -> None:
        assert _parse_hash_line(":") is None

    def test_lm_nt_with_extra_colon(self) -> None:
        lm = "aabbccdd11223344aabbccdd11223344"
        assert _parse_hash_line(f"{lm}:11223344aabbccdd:extra") is None


class TestParseHashLines:
    def test_mixed_valid_invalid(self) -> None:
        lines = [
            "aabbccdd11223344aabbccdd11223344",
            "bad line",
            "aabbccdd11223344aabbccdd11223344:11223344aabbccdd11223344aabbccdd",
        ]
        logger = Logger(verbosity=0)
        result = _parse_hash_lines(lines, logger)
        assert len(result) == 2
        assert result[0] == ("", "aabbccdd11223344aabbccdd11223344")
        assert result[1][0] == "aabbccdd11223344aabbccdd11223344"


class TestParseHashLinesEdgeCases:
    def test_all_invalid(self) -> None:
        logger = Logger(verbosity=0)
        result = _parse_hash_lines(["bad", "also bad", "nope"], logger)
        assert result == []

    def test_empty_list(self) -> None:
        logger = Logger(verbosity=0)
        result = _parse_hash_lines([], logger)
        assert result == []


class TestValidateHexKey:
    def test_valid_rc4_key(self) -> None:
        key = "a" * RC4_KEY_HEX_LEN
        assert _validate_hex_key(key, RC4_KEY_HEX_LEN) == key

    def test_valid_aes128_key(self) -> None:
        key = "b" * AES128_KEY_HEX_LEN
        assert _validate_hex_key(key, AES128_KEY_HEX_LEN) == key

    def test_valid_aes256_key(self) -> None:
        key = "c" * AES256_KEY_HEX_LEN
        assert _validate_hex_key(key, AES256_KEY_HEX_LEN) == key

    def test_wrong_length(self) -> None:
        assert _validate_hex_key("a" * 48, RC4_KEY_HEX_LEN) is None

    def test_invalid_hex_chars(self) -> None:
        assert _validate_hex_key("z" * RC4_KEY_HEX_LEN, RC4_KEY_HEX_LEN) is None

    def test_strips_whitespace(self) -> None:
        key = "a" * RC4_KEY_HEX_LEN
        assert _validate_hex_key(f"  {key}  ", RC4_KEY_HEX_LEN) == key

    def test_normalizes_case(self) -> None:
        key = "A" * AES256_KEY_HEX_LEN
        result = _validate_hex_key(key, AES256_KEY_HEX_LEN)
        assert result == key.lower()

    def test_empty_string(self) -> None:
        assert _validate_hex_key("", RC4_KEY_HEX_LEN) is None


class TestDetectKerberosKey:
    def test_rc4_32_hex(self) -> None:
        key = "a" * RC4_KEY_HEX_LEN
        result = _detect_kerberos_key(key)
        assert result is not None
        rc4, aes128, aes256, label = result
        assert rc4 == key
        assert aes128 is None
        assert aes256 is None
        assert label == "RC4"

    def test_aes256_64_hex(self) -> None:
        key = "b" * AES256_KEY_HEX_LEN
        result = _detect_kerberos_key(key)
        assert result is not None
        rc4, _aes128, aes256, label = result
        assert rc4 is None
        assert aes256 == key
        assert label == "AES256"

    def test_invalid_length(self) -> None:
        assert _detect_kerberos_key("a" * 48) is None

    def test_invalid_chars(self) -> None:
        assert _detect_kerberos_key("z" * RC4_KEY_HEX_LEN) is None

    def test_32_hex_defaults_to_rc4(self) -> None:
        key = "a" * RC4_KEY_HEX_LEN
        result = _detect_kerberos_key(key, EncryptionType.RC4)
        assert result is not None
        assert result[3] == "RC4"
        assert result[0] == key

    def test_32_hex_with_aes128_etype(self) -> None:
        key = "a" * AES128_KEY_HEX_LEN
        result = _detect_kerberos_key(key, EncryptionType.AES128)
        assert result is not None
        rc4, aes128, aes256, label = result
        assert rc4 is None
        assert aes128 == key
        assert aes256 is None
        assert label == "AES128"

    def test_64_hex_ignores_etype(self) -> None:
        key = "b" * AES256_KEY_HEX_LEN
        result = _detect_kerberos_key(key, EncryptionType.AES128)
        assert result is not None
        assert result[3] == "AES256"
        assert result[2] == key

    def test_empty_string(self) -> None:
        assert _detect_kerberos_key("") is None

    def test_32_hex_with_aes256_etype_still_rc4(self) -> None:
        key = "a" * RC4_KEY_HEX_LEN
        result = _detect_kerberos_key(key, EncryptionType.AES256)
        assert result is not None
        assert result[3] == "RC4"
        assert result[0] == key


class TestHashDisplay:
    def test_nt_hash(self) -> None:
        assert _hash_display("aabb") == "aabb"

    def test_none(self) -> None:
        assert _hash_display(None) is None

    def test_empty_string(self) -> None:
        assert _hash_display("") == ""
