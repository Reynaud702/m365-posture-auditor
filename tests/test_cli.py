"""Tests for CLI argument parsing."""
import os

import pytest

from m365audit import cli


def test_parser_requires_tenant_id():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parser_accepts_minimum_args():
    parser = cli.build_parser()
    args = parser.parse_args([
        "--tenant-id", "t-guid",
        "--client-id", "c-guid",
        "--client-secret", "s",
        "--tenant-name", "Acme",
    ])
    assert args.tenant_id == "t-guid"
    assert args.tenant_name == "Acme"


def test_parser_only_filter():
    parser = cli.build_parser()
    args = parser.parse_args([
        "--tenant-id", "t", "--client-id", "c", "--client-secret", "s",
        "--tenant-name", "X", "--only", "ID-001,EM-001",
    ])
    assert args.only == "ID-001,EM-001"


def test_run_errors_on_missing_secret(capsys, monkeypatch):
    monkeypatch.delenv("M365_CLIENT_SECRET", raising=False)
    parser = cli.build_parser()
    args = parser.parse_args([
        "--tenant-id", "t", "--client-id", "c", "--tenant-name", "X",
    ])
    rc = cli.run(args)
    assert rc == 2
    assert "M365_CLIENT_SECRET" in capsys.readouterr().err
