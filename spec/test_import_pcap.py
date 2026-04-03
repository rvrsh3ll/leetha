"""Tests for PCAP import module."""
import pytest
from pathlib import Path
from leetha.import_pcap import validate_pcap_file, SUPPORTED_EXTENSIONS


def test_supported_extensions():
    assert ".pcap" in SUPPORTED_EXTENSIONS
    assert ".pcapng" in SUPPORTED_EXTENSIONS
    assert ".cap" in SUPPORTED_EXTENSIONS


def test_validate_pcap_file_missing(tmp_path):
    result = validate_pcap_file(tmp_path / "nonexistent.pcap")
    assert result is not None  # returns error string


def test_validate_pcap_file_wrong_extension(tmp_path):
    bad_file = tmp_path / "data.txt"
    bad_file.write_text("not a pcap")
    result = validate_pcap_file(bad_file)
    assert result is not None


def test_validate_pcap_file_too_large(tmp_path):
    big_file = tmp_path / "huge.pcap"
    big_file.write_bytes(b"\x00" * 100)
    result = validate_pcap_file(big_file, max_size_mb=0)  # 0 MB limit
    assert result is not None


def test_validate_pcap_file_ok(tmp_path):
    good_file = tmp_path / "test.pcap"
    good_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    result = validate_pcap_file(good_file)
    assert result is None  # no error
