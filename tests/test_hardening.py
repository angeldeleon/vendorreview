"""Hardening: file handling, the review history on disk, and the HTTP client.

Every path this tool opens points at something somebody else put there. The
intake arrives by email, the evidence lands in a shared drop directory that
procurement can write to, and the default state path is relative — which in CI
means inside a checked-out repository, i.e. attacker-controlled content.
"""

from __future__ import annotations

import os
import socket
import stat
from pathlib import Path

import httpx
import pytest

from conftest import write
from test_pipeline import MINIMAL, _review
from vendorreview.baseline import BaselineStore, StateError
from vendorreview.evidence.reader import load_document
from vendorreview.httpclient import (
    MAX_RESPONSE_BYTES,
    HTTPError,
    assert_api_url,
    post_json,
)
from vendorreview.intake import load_intake
from vendorreview.validation import ValidationError

# --------------------------------------------------------------------------
# File handling
# --------------------------------------------------------------------------


def test_the_intake_reader_refuses_a_symlink(tmp_path) -> None:
    real = write(tmp_path, "real.yml", MINIMAL)
    link = tmp_path / "link.yml"
    link.symlink_to(real)
    with pytest.raises(ValidationError):
        load_intake(link)


def test_an_evidence_symlink_is_refused_without_crashing(tmp_path) -> None:
    # An evidence folder is usually a shared drop directory. Following a symlink
    # out of it would let whoever can write there aim this reader at any file the
    # running account can open.
    secret = write(tmp_path, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----")
    link = tmp_path / "soc2.txt"
    link.symlink_to(secret)
    doc = load_document(link)
    assert not doc.readable
    assert "-----BEGIN" not in "\n".join(doc.lines)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFO support")
def test_a_fifo_in_the_evidence_folder_does_not_hang_the_run(tmp_path) -> None:
    fifo = tmp_path / "soc2.txt"
    os.mkfifo(fifo)
    doc = load_document(fifo)  # O_NONBLOCK, then the regular-file check
    assert not doc.readable


def test_a_directory_is_not_a_document(tmp_path) -> None:
    assert not load_document(tmp_path).readable


def test_the_document_size_cap_is_enforced(tmp_path) -> None:
    path = write(tmp_path, "big.txt", "line\n" * 100_000)
    doc = load_document(path, max_bytes=1024)
    assert not doc.readable
    assert "limit" in " ".join(doc.problems)


def test_document_line_and_page_caps_mark_truncation(tmp_path) -> None:
    from vendorreview.evidence.reader import MAX_LINES

    path = write(tmp_path, "long.txt", "x\n" * (MAX_LINES + 50))
    doc = load_document(path)
    assert doc.truncated
    assert len(doc.lines) <= MAX_LINES


def test_a_truncated_report_leaves_the_rest_unknown_not_absent(tmp_path) -> None:
    from datetime import date

    from vendorreview.evidence.soc2 import parse_soc2
    from vendorreview.models import Attestation

    path = write(tmp_path, "soc2.txt", "SOC 2 Type II\n" + ("filler\n" * 80_000))
    report = parse_soc2(load_document(path), as_of=date(2026, 6, 1))
    assert report.period_current is Attestation.NOT_EVIDENCED
    assert any("truncated" in p for p in report.problems)


def test_the_intake_size_cap_is_enforced(tmp_path) -> None:
    path = write(tmp_path, "huge.yml", "vendor: v\nservice: " + "z" * 600_000)
    with pytest.raises(ValidationError):
        load_intake(path)


# --------------------------------------------------------------------------
# The review history on disk
# --------------------------------------------------------------------------


def test_the_history_refuses_a_symlinked_parent_directory(tmp_path) -> None:
    """O_NOFOLLOW covers the final component only.

    Path.mkdir(exist_ok=True) accepts a pre-existing symlink-to-directory because
    is_dir() follows links, so a planted `.vendorreview -> /tmp/attacker`
    redirected the whole database — and that database names every vendor the
    organisation assessed and every gap each one had.
    """
    elsewhere = tmp_path / "attacker"
    elsewhere.mkdir()
    link = tmp_path / "state"
    link.symlink_to(elsewhere)
    with pytest.raises(StateError, match="symlink"):
        BaselineStore(link / "reviews.db", scope="a").save(_review())


def test_the_history_refuses_a_symlinked_database_file(tmp_path) -> None:
    target = tmp_path / "target.db"
    target.write_text("", encoding="utf-8")
    link = tmp_path / "reviews.db"
    link.symlink_to(target)
    with pytest.raises(StateError):
        BaselineStore(link, scope="a").save(_review())


def test_the_history_refuses_a_fifo_at_its_path(tmp_path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFO support")
    fifo = tmp_path / "reviews.db"
    os.mkfifo(fifo)
    with pytest.raises(StateError):
        BaselineStore(fifo, scope="a").save(_review())


def test_permissive_modes_are_repaired_through_the_descriptor(tmp_path) -> None:
    path = tmp_path / "reviews.db"
    store = BaselineStore(path, scope="a")
    store.save(_review())
    path.chmod(0o666)
    store.previous()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_the_history_is_created_before_sqlite_touches_it(tmp_path) -> None:
    # sqlite3 creates at 0644 and chmod-ing afterwards leaves a window.
    path = tmp_path / "nested" / "reviews.db"
    BaselineStore(path, scope="a").save(_review())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# --------------------------------------------------------------------------
# The HTTP client
# --------------------------------------------------------------------------


def test_https_to_a_public_host_is_accepted(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolves("93.184.216.34"))
    assert assert_api_url("https://api.example.test/v1/messages")


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "0.0.0.0", "224.0.0.1"],
)
def test_internal_addresses_are_refused(monkeypatch, address: str) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolves(address))
    with pytest.raises(ValidationError, match="not a public address"):
        assert_api_url("https://gateway.example.test/v1")


def test_ipv4_mapped_spellings_are_refused(monkeypatch) -> None:
    # Checking only the textual form would let ::ffff:169.254.169.254 through a
    # filter that blocks the v4 spelling.
    monkeypatch.setattr(
        socket, "getaddrinfo", _resolves("::ffff:169.254.169.254", family=socket.AF_INET6)
    )
    with pytest.raises(ValidationError, match="not a public address"):
        assert_api_url("https://gateway.example.test/v1")


def test_a_self_hosted_gateway_can_be_allowed_deliberately(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolves("10.0.0.5"))
    assert assert_api_url("https://gateway.internal/v1", allow_internal=True)


def test_plain_http_is_refused_because_the_key_goes_on_the_wire() -> None:
    with pytest.raises(ValidationError, match="plain HTTP"):
        assert_api_url("http://api.example.test/v1")


def test_unsupported_schemes_are_refused() -> None:
    for url in ("file:///etc/passwd", "ftp://example.test", "not a url"):
        with pytest.raises(ValidationError):
            assert_api_url(url)


def test_credentials_in_the_url_are_refused() -> None:
    with pytest.raises(ValidationError, match="credentials in a URL"):
        assert_api_url("https://user:pass@api.example.test/v1")


def test_a_header_with_a_newline_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolves("93.184.216.34"))
    with pytest.raises(ValidationError, match="newline"):
        post_json(
            "https://api.example.test/v1",
            {},
            headers={"x-api-key": "abc\r\nx-injected: 1"},
        )


def test_a_redirect_is_refused_rather_than_followed(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolves("93.184.216.34"))
    _stub_transport(
        monkeypatch, httpx.Response(302, headers={"location": "http://169.254.169.254/"})
    )
    with pytest.raises(HTTPError, match="redirect"):
        post_json("https://api.example.test/v1", {}, headers={})


def test_an_oversized_body_is_abandoned_mid_transfer(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolves("93.184.216.34"))
    oversized = b"x" * (MAX_RESPONSE_BYTES + 1024)
    _stub_transport(monkeypatch, httpx.Response(200, content=oversized))
    with pytest.raises(HTTPError, match="exceeds"):
        post_json("https://api.example.test/v1", {}, headers={})


def test_an_error_status_reports_a_truncated_body(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolves("93.184.216.34"))
    _stub_transport(monkeypatch, httpx.Response(401, content=b'{"error":"bad key"}'))
    with pytest.raises(HTTPError, match="401"):
        post_json("https://api.example.test/v1", {}, headers={})


def test_a_non_json_body_is_an_error(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolves("93.184.216.34"))
    _stub_transport(monkeypatch, httpx.Response(200, content=b"<html>maintenance</html>"))
    with pytest.raises(HTTPError, match="not JSON"):
        post_json("https://api.example.test/v1", {}, headers={})


def test_a_json_array_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolves("93.184.216.34"))
    _stub_transport(monkeypatch, httpx.Response(200, content=b"[1,2,3]"))
    with pytest.raises(HTTPError, match="not an object"):
        post_json("https://api.example.test/v1", {}, headers={})


def test_a_transport_failure_does_not_leak_the_url(monkeypatch) -> None:
    # A full URL in an error string reaches logs and reports, and query strings
    # carry tokens more often than anyone intends.
    monkeypatch.setattr(socket, "getaddrinfo", _resolves("93.184.216.34"))

    def failing(self, request):  # type: ignore[no-untyped-def]
        raise httpx.ConnectError("refused", request=request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", failing)
    with pytest.raises(HTTPError) as caught:
        post_json("https://api.example.test/v1?token=secret123", {}, headers={})
    assert "secret123" not in str(caught.value)


def test_a_successful_response_is_decoded(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _resolves("93.184.216.34"))
    _stub_transport(monkeypatch, httpx.Response(200, content=b'{"ok":true}'))
    assert post_json("https://api.example.test/v1", {}, headers={}) == {"ok": True}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _resolves(address: str, family: int = socket.AF_INET):  # type: ignore[no-untyped-def]
    def resolver(host, port, *args, **kwargs):  # type: ignore[no-untyped-def]
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0))]

    return resolver


def _stub_transport(monkeypatch, response: httpx.Response) -> None:  # type: ignore[no-untyped-def]
    def handle(self, request):  # type: ignore[no-untyped-def]
        response.request = request
        return response

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle)


def test_the_gitignore_covers_the_review_history() -> None:
    # The history names every vendor assessed and every gap each one had.
    text = (Path(__file__).resolve().parents[1] / ".gitignore").read_text(encoding="utf-8")
    assert ".vendorreview/" in text
