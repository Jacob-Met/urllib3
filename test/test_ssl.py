from __future__ import annotations

import ssl
import sys
import typing
from unittest import mock

import pytest

from urllib3.exceptions import ProxySchemeUnsupported, SSLError
from urllib3.util import ssl_


class TestSSL:
    @pytest.mark.parametrize(
        "addr",
        [
            # IPv6
            "::1",
            "::",
            "FE80::8939:7684:D84b:a5A4%251",
            # IPv4
            "127.0.0.1",
            "8.8.8.8",
            b"127.0.0.1",
            # Non-standard IPv4 forms accepted by socket.connect
            "2130706433",  # decimal integer
            "0x7f000001",  # hex integer
            "0177.0.0.01",  # dotted octal
            "0x7f.0x0.0x0.0x1",  # dotted hex
            "127.1",  # 2-part
            "127.0.1",  # 3-part
            # IPv6 w/ Zone IDs
            "FE80::8939:7684:D84b:a5A4%251",
            b"FE80::8939:7684:D84b:a5A4%251",
            "FE80::8939:7684:D84b:a5A4%19",
            b"FE80::8939:7684:D84b:a5A4%19",
        ],
    )
    def test_is_ipaddress_true(self, addr: bytes | str) -> None:
        assert ssl_.is_ipaddress(addr)

    @pytest.mark.parametrize(
        "addr",
        [
            "www.python.org",
            b"www.python.org",
            "v2.sg.media-imdb.com",
            b"v2.sg.media-imdb.com",
        ],
    )
    def test_is_ipaddress_false(self, addr: bytes | str) -> None:
        assert not ssl_.is_ipaddress(addr)

    def test_create_urllib3_context_set_ciphers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ciphers = "ECDH+AESGCM:ECDH+CHACHA20"
        context = mock.create_autospec(ssl_.SSLContext)
        context.set_ciphers = mock.Mock()
        context.options = 0
        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        assert ssl_.create_urllib3_context(ciphers=ciphers) is context

        assert context.set_ciphers.call_count == 1
        assert context.set_ciphers.call_args == mock.call(ciphers)

    def test_create_urllib3_no_context(self) -> None:
        with mock.patch("urllib3.util.ssl_.SSLContext", None):
            with pytest.raises(TypeError):
                ssl_.create_urllib3_context()

    def test_create_urllib3_context_default_verify_flags(self) -> None:
        context = ssl_.create_urllib3_context()
        if sys.version_info >= (3, 13):
            assert context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
            assert context.verify_flags & ssl.VERIFY_X509_STRICT
        else:
            assert not (context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN)
            assert not (context.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_create_urllib3_context_custom_verify_flags(self) -> None:
        context = ssl_.create_urllib3_context()
        assert not (context.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF)
        context = ssl_.create_urllib3_context(verify_flags=ssl.VERIFY_CRL_CHECK_LEAF)
        assert context.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF

    def test_wrap_socket_given_context_no_load_default_certs(self) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.load_default_certs = mock.Mock()

        sock = mock.Mock()
        ssl_.ssl_wrap_socket(sock, ssl_context=context)

        context.load_default_certs.assert_not_called()

    def test_wrap_socket_given_ca_certs_no_load_default_certs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.load_default_certs = mock.Mock()
        context.options = 0

        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        sock = mock.Mock()
        ssl_.ssl_wrap_socket(sock, ca_certs="/tmp/fake-file")

        context.load_default_certs.assert_not_called()
        context.load_verify_locations.assert_called_with("/tmp/fake-file", None, None)

    def test_wrap_socket_default_loads_default_certs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.load_default_certs = mock.Mock()
        context.options = 0

        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        sock = mock.Mock()
        ssl_.ssl_wrap_socket(sock)

        context.load_default_certs.assert_called_with()

    def test_wrap_socket_no_ssltransport(self) -> None:
        with mock.patch("urllib3.util.ssl_.SSLTransport", None):
            with pytest.raises(ProxySchemeUnsupported):
                sock = mock.Mock()
                ssl_.ssl_wrap_socket(sock, tls_in_tls=True)

    @pytest.mark.parametrize(
        ["pha", "expected_pha", "cert_reqs"],
        [
            (None, None, None),
            (None, None, ssl.CERT_NONE),
            (None, None, ssl.CERT_OPTIONAL),
            (None, None, ssl.CERT_REQUIRED),
            (False, True, None),
            (False, True, ssl.CERT_NONE),
            (False, True, ssl.CERT_OPTIONAL),
            (False, True, ssl.CERT_REQUIRED),
            (True, True, None),
            (True, True, ssl.CERT_NONE),
            (True, True, ssl.CERT_OPTIONAL),
            (True, True, ssl.CERT_REQUIRED),
        ],
    )
    def test_create_urllib3_context_pha(
        self,
        monkeypatch: pytest.MonkeyPatch,
        pha: bool | None,
        expected_pha: bool | None,
        cert_reqs: int | None,
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.set_ciphers = mock.Mock()
        context.options = 0
        context.post_handshake_auth = pha
        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        assert ssl_.create_urllib3_context(cert_reqs=cert_reqs) is context

        assert context.post_handshake_auth == expected_pha

    def test_create_urllib3_context_default_ciphers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.set_ciphers = mock.Mock()
        context.options = 0
        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        ssl_.create_urllib3_context()

        context.set_ciphers.assert_not_called()

    # PROTOCOL_TLS_SERVER is used as a stand-in for any non-default ssl_version.
    # PROTOCOL_TLSv1/TLSv1_2 are unavailable when Python is built with OpenSSL 4+.
    @pytest.mark.parametrize(
        "kwargs",
        [
            {
                "ssl_version": ssl.PROTOCOL_TLS_SERVER,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
            {
                "ssl_version": ssl.PROTOCOL_TLS_SERVER,
                "ssl_maximum_version": ssl.TLSVersion.TLSv1,
            },
            {
                "ssl_version": ssl.PROTOCOL_TLS_SERVER,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
                "ssl_maximum_version": ssl.TLSVersion.MAXIMUM_SUPPORTED,
            },
        ],
    )
    def test_create_urllib3_context_ssl_version_and_ssl_min_max_version_errors(
        self, kwargs: dict[str, typing.Any]
    ) -> None:
        with pytest.raises(ValueError) as e:
            ssl_.create_urllib3_context(**kwargs)

        assert str(e.value) == (
            "Can't specify both 'ssl_version' and either 'ssl_minimum_version' or 'ssl_maximum_version'"
        )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {
                "ssl_version": ssl.PROTOCOL_TLS,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
            {
                "ssl_version": ssl.PROTOCOL_TLS_CLIENT,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
            {
                "ssl_version": None,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
        ],
    )
    def test_create_urllib3_context_ssl_version_and_ssl_min_max_version_no_warning(
        self, kwargs: dict[str, typing.Any]
    ) -> None:
        ssl_.create_urllib3_context(**kwargs)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"ssl_version": ssl.PROTOCOL_TLS_SERVER, "ssl_minimum_version": None},
            {"ssl_version": ssl.PROTOCOL_TLS_SERVER, "ssl_maximum_version": None},
            {
                "ssl_version": ssl.PROTOCOL_TLS_SERVER,
                "ssl_minimum_version": None,
                "ssl_maximum_version": None,
            },
        ],
    )
    def test_create_urllib3_context_ssl_version_and_ssl_min_max_version_no_error(
        self, kwargs: dict[str, typing.Any]
    ) -> None:
        with pytest.warns(
            FutureWarning,
            match=r"'ssl_version' option is deprecated and will be removed in "
            r"urllib3 v3\.0\. Instead use 'ssl_minimum_version'",
        ):
            ssl_.create_urllib3_context(**kwargs)

    def test_assert_fingerprint_raises_exception_on_none_cert(self) -> None:
        with pytest.raises(SSLError):
            ssl_.assert_fingerprint(
                cert=None, fingerprint="55:39:BF:70:05:12:43:FA:1F:D1:BF:4E:E8:1B:07:1D"
            )

    @pytest.mark.parametrize(
        "fingerprint",
        [
            "g" * 32,
            "g" * 40,
            "g" * 64,
            "a" * 39 + "g",
            "GG:" * 19 + "GG",
        ],
    )
    def test_assert_fingerprint_raises_sslerror_on_non_hexadecimal(
        self, fingerprint: str
    ) -> None:
        with pytest.raises(SSLError):
            ssl_.assert_fingerprint(b"certificate", fingerprint)


def test_shared_context_parallel_connection_setup() -> None:
    """Configuring a shared context must not race with other TLS handshakes."""
    import time
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    context = mock.create_autospec(ssl_.SSLContext)
    barrier = Barrier(12)

    def slow_load(*args: object, **kw: object) -> None:
        time.sleep(0.01)

    context.load_verify_locations.side_effect = slow_load

    def connect() -> None:
        barrier.wait(timeout=5)
        ssl_.ssl_wrap_socket(
            mock.Mock(),
            ssl_context=context,
            ca_certs="trust.pem",
            certfile="client.pem",
        )

    with ThreadPoolExecutor(max_workers=12) as executor:
        list(executor.map(lambda _: connect(), range(12)))

    assert context.wrap_socket.call_count == 12
    assert context.load_verify_locations.call_count == 1
    assert context.load_cert_chain.call_count == 1
    assert context.set_alpn_protocols.call_count == 1


def test_shared_context_rotation_requires_a_new_context(
    tmp_path: typing.Any,
) -> None:
    """Never silently keep stale CA material when a configured file changes."""
    ca = tmp_path / "trust.pem"
    ca.write_bytes(b"CA version one")
    context = mock.create_autospec(ssl_.SSLContext)
    ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, ca_certs=str(ca))
    ca.write_bytes(b"CA version two has different length")

    with pytest.raises(SSLError, match="new SSLContext"):
        ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, ca_certs=str(ca))
    assert context.wrap_socket.call_count == 1


def test_shared_context_ca_directory_replacement_requires_new_context(
    tmp_path: typing.Any,
) -> None:
    ca_dir = tmp_path / "certs"
    ca_dir.mkdir()
    (ca_dir / "one.pem").write_bytes(b"one")
    context = mock.create_autospec(ssl_.SSLContext)
    ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, ca_cert_dir=str(ca_dir))
    (ca_dir / "two.pem").write_bytes(b"two")

    with pytest.raises(SSLError, match="new SSLContext"):
        ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, ca_cert_dir=str(ca_dir))
    assert context.load_verify_locations.call_count == 1
    assert context.wrap_socket.call_count == 1


def test_shared_context_alpn_policy_change_requires_new_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = mock.create_autospec(ssl_.SSLContext)
    ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context)
    monkeypatch.setattr(ssl_, "ALPN_PROTOCOLS", ["h2", "http/1.1"])
    with pytest.raises(SSLError, match="new SSLContext"):
        ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context)
    assert context.set_alpn_protocols.call_count == 1


def test_shared_context_conflicting_certificates_fail_before_handshake() -> None:
    context = mock.create_autospec(ssl_.SSLContext)
    ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, ca_certs="one.pem")

    with pytest.raises(SSLError, match="new SSLContext"):
        ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, ca_certs="two.pem")
    assert context.wrap_socket.call_count == 1


def test_shared_context_failed_setup_is_retryable() -> None:
    context = mock.create_autospec(ssl_.SSLContext)
    context.load_verify_locations.side_effect = [OSError("unreadable CA"), None]

    with pytest.raises(SSLError, match="unreadable CA"):
        ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, ca_certs="ca.pem")
    ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, ca_certs="ca.pem")
    assert context.load_verify_locations.call_count == 2
    assert context.wrap_socket.call_count == 1


def test_shared_connection_does_not_rewrite_verification_on_reuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from urllib3 import connection

    class ObservedContext(ssl.SSLContext):
        def __new__(cls) -> ObservedContext:
            return super().__new__(cls, ssl.PROTOCOL_TLS_CLIENT)

        def __init__(self) -> None:
            self.writes: list[str] = []

        def __setattr__(self, name: str, value: typing.Any) -> None:
            if name in ("verify_mode", "check_hostname"):
                self.writes.append(name)
            super().__setattr__(name, value)

    ctx = ObservedContext()
    sock = mock.Mock()
    monkeypatch.setattr(ssl_, "_ssl_wrap_socket_impl", lambda *args: sock)
    kwargs: dict[str, typing.Any] = dict(
        sock=mock.Mock(),
        cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=None,
        ssl_minimum_version=None,
        ssl_maximum_version=None,
        cert_file=None,
        key_file=None,
        key_password=None,
        ca_certs=None,
        ca_cert_dir=None,
        ca_cert_data=None,
        assert_hostname=False,
        assert_fingerprint=None,
        server_hostname="localhost",
        ssl_context=ctx,
    )
    connection._ssl_wrap_socket_and_match_hostname(**kwargs)
    first_writes = list(ctx.writes)
    assert first_writes == ["check_hostname"]
    connection._ssl_wrap_socket_and_match_hostname(**kwargs)
    assert ctx.writes == first_writes


def test_shared_context_does_not_reuse_disabled_hostname_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from urllib3 import connection

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(ssl_, "_ssl_wrap_socket_impl", lambda *args: mock.Mock())
    kwargs: dict[str, typing.Any] = dict(
        sock=mock.Mock(),
        cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=None,
        ssl_minimum_version=None,
        ssl_maximum_version=None,
        cert_file=None,
        key_file=None,
        key_password=None,
        ca_certs=None,
        ca_cert_dir=None,
        ca_cert_data=None,
        assert_hostname=False,
        assert_fingerprint=None,
        server_hostname="localhost",
        ssl_context=context,
    )
    connection._ssl_wrap_socket_and_match_hostname(**kwargs)
    assert context.check_hostname is False

    # This connection expects OpenSSL's built-in hostname verification,
    # which is now disabled on the shared context by the earlier caller.
    kwargs["assert_hostname"] = None
    with pytest.raises(SSLError, match="new SSLContext"):
        connection._ssl_wrap_socket_and_match_hostname(**kwargs)


def test_default_connection_loads_system_trust_only_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The high-level caller already loads OS CAs into a fresh context."""
    from urllib3 import connection

    context = mock.create_autospec(ssl_.SSLContext)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    monkeypatch.setattr(connection, "create_urllib3_context", lambda *a, **k: context)
    monkeypatch.setattr(ssl_, "_ssl_wrap_socket_impl", lambda *args: mock.Mock())
    connection._ssl_wrap_socket_and_match_hostname(
        sock=mock.Mock(),
        cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=None,
        ssl_minimum_version=None,
        ssl_maximum_version=None,
        cert_file=None,
        key_file=None,
        key_password=None,
        ca_certs=None,
        ca_cert_dir=None,
        ca_cert_data=None,
        assert_hostname=None,
        assert_fingerprint=None,
        server_hostname="localhost",
        ssl_context=None,
    )
    assert context.load_default_certs.call_count == 1


def test_fresh_context_does_not_use_shared_context_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(ssl_, "_ssl_wrap_socket_impl", lambda *args: mock.Mock())
    monkeypatch.setattr(
        ssl_,
        "_configure_shared_ssl_context",
        lambda *args, **kwargs: pytest.fail("fresh SSLContext used shared lock"),
    )
    ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, _context_is_fresh=True)


def test_shared_context_ca_dir_detects_inplace_rotation(
    tmp_path: typing.Any,
) -> None:
    ca_dir = tmp_path / "certs"
    ca_dir.mkdir()
    cert = ca_dir / "hash.0"
    cert.write_bytes(b"old cert")
    context = mock.create_autospec(ssl_.SSLContext)
    ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, ca_cert_dir=str(ca_dir))
    before = ca_dir.stat().st_mtime_ns
    cert.write_bytes(b"new certificate data")
    assert ca_dir.stat().st_mtime_ns == before

    with pytest.raises(SSLError, match="new SSLContext"):
        ssl_.ssl_wrap_socket(mock.Mock(), ssl_context=context, ca_cert_dir=str(ca_dir))
    assert context.wrap_socket.call_count == 1
