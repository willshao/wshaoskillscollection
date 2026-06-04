"""Tests for _shared.log_discovery."""
from __future__ import annotations

from pathlib import Path

import pytest

import log_discovery


def test_classify_iis_log(sample_iis_log: Path):
    assert log_discovery.classify_file(sample_iis_log) == log_discovery.IIS_KIND


def test_classify_ftp_log(fixtures_dir: Path):
    p = fixtures_dir / "sample_ftp.log"
    assert log_discovery.classify_file(p) == log_discovery.FTP_KIND


def test_classify_httperr_by_header(fixtures_dir: Path):
    p = fixtures_dir / "httperr1.log"
    assert log_discovery.classify_file(p) == log_discovery.HTTPERR_KIND


def test_classify_httperr_by_filename(tmp_path: Path):
    # No #Software header; rely on filename.
    p = tmp_path / "httperr3.log"
    p.write_text("garbage line\n", encoding="utf-8")
    assert log_discovery.classify_file(p) == log_discovery.HTTPERR_KIND


def test_discover_logs_mixed_folder(fixtures_dir: Path, tmp_path: Path):
    # Copy the three fixture logs into a fresh tmp dir so we control contents.
    import shutil
    for name in ("sample_iis.log", "sample_ftp.log", "httperr1.log"):
        shutil.copy(fixtures_dir / name, tmp_path / name)
    # And one unknown file for completeness.
    (tmp_path / "random.log").write_text("not a log\n", encoding="utf-8")

    disc = log_discovery.discover_logs(tmp_path)
    assert len(disc.get(log_discovery.IIS_KIND)) == 1
    assert len(disc.get(log_discovery.FTP_KIND)) == 1
    assert len(disc.get(log_discovery.HTTPERR_KIND)) == 1
    assert len(disc.get(log_discovery.UNKNOWN_KIND)) == 1
    assert disc.total == 4


def test_discover_logs_recursive_vs_flat(fixtures_dir: Path, tmp_path: Path):
    import shutil
    sub = tmp_path / "nested" / "deep"
    sub.mkdir(parents=True)
    shutil.copy(fixtures_dir / "sample_iis.log", sub / "u_ex260526.log")

    deep_recursive = log_discovery.discover_logs(tmp_path, recursive=True)
    shallow = log_discovery.discover_logs(tmp_path, recursive=False)

    assert len(deep_recursive.get(log_discovery.IIS_KIND)) == 1
    assert len(shallow.get(log_discovery.IIS_KIND)) == 0


def test_discover_logs_single_file(sample_iis_log: Path):
    disc = log_discovery.discover_logs(sample_iis_log)
    assert disc.get(log_discovery.IIS_KIND) == [sample_iis_log]
