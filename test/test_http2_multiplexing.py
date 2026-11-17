from __future__ import annotations

import queue
import socket
import ssl
import threading
import time
from unittest.mock import Mock

import h2.config
import h2.connection
import h2.events
import trustme

import urllib3
from urllib3.http2 import extract_from_urllib3, inject_into_urllib3


def test_two_http2_streams_share_one_tcp_connection() -> None:
    """Two concurrent requests must reach the server before either reply."""
    ca = trustme.CA()
    server_cert = ca.issue_cert("localhost")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.set_alpn_protocols(["h2"])
    server_cert.configure_cert(server_context)
    client_context = ssl.create_default_context()
    ca.configure_trust(client_context)
    client_context.set_alpn_protocols(["h2"])

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(5)
    port = listener.getsockname()[1]

    observed: queue.Queue[tuple[bool, int, int]] = queue.Queue()
    errors: queue.Queue[BaseException] = queue.Queue()

    def serve() -> None:
        stream_paths: dict[int, bytes] = {}
        completed: set[int] = set()
        replied = False
        start = time.monotonic()
        try:
            with listener:
                raw, _ = listener.accept()
                with server_context.wrap_socket(raw, server_side=True) as conn:
                    conn.settimeout(0.1)
                    h2conn = h2.connection.H2Connection(
                        config=h2.config.H2Configuration(client_side=False)
                    )
                    h2conn.initiate_connection()
                    conn.sendall(h2conn.data_to_send())
                    while time.monotonic() - start < 4:
                        try:
                            chunk = conn.recv(65535)
                        except TimeoutError:
                            chunk = None
                        if chunk == b"":
                            break
                        if chunk:
                            for ev in h2conn.receive_data(chunk):
                                if isinstance(ev, h2.events.RequestReceived):
                                    stream_paths[ev.stream_id] = dict(ev.headers)[
                                        b":path"
                                    ]
                                if isinstance(ev, h2.events.StreamEnded):
                                    completed.add(ev.stream_id)
                        if not replied and (
                            len(stream_paths) >= 2 or time.monotonic() - start > 2
                        ):
                            observed.put((len(stream_paths) >= 2, len(stream_paths), 1))
                            for stream_id, path in stream_paths.items():
                                h2conn.send_headers(stream_id, [(b":status", b"200")])
                                h2conn.send_data(
                                    stream_id, b"reply:" + path, end_stream=True
                                )
                            conn.sendall(h2conn.data_to_send())
                            replied = True
                        elif replied and len(stream_paths) > len(completed):
                            pass
                        if replied and len(stream_paths) >= 2:
                            break
        except Exception as exc:  # noqa: BLE001 - test thread must relay errors
            errors.put(exc)

    threading.Thread(target=serve, daemon=True).start()
    inject_into_urllib3()
    results: queue.Queue[tuple[str, bytes | BaseException]] = queue.Queue()
    http = urllib3.PoolManager(
        maxsize=1, block=True, retries=False, ssl_context=client_context
    )

    def fetch(path: str) -> None:
        try:
            resp = http.request("GET", f"https://localhost:{port}{path}", timeout=3)
            results.put((path, resp.data))
        except Exception as exc:  # noqa: BLE001 - test thread must relay errors
            results.put((path, exc))

    try:
        t1 = threading.Thread(target=fetch, args=("/first",), daemon=True)
        t2 = threading.Thread(target=fetch, args=("/second",), daemon=True)
        t1.start()
        t2.start()
        t1.join(7)
        t2.join(7)
        assert not t1.is_alive() and not t2.is_alive(), "requests hung"
        assert errors.empty(), str(list(errors.queue))
        assert not observed.empty(), "no H2 response exchange"
        overlap, streams, tcp_connections = observed.get_nowait()
        assert (
            overlap
        ), f"expected 2 concurrent H2 streams; observed {streams} on {tcp_connections} TCP connection"
        got = dict(results.queue)
        assert got == {
            "/first": b"reply:/first",
            "/second": b"reply:/second",
        }
    finally:
        http.clear()
        extract_from_urllib3()
        listener.close()


def test_peer_max_concurrent_streams_waits_without_new_socket() -> None:
    """The H2 peer's SETTINGS limit releases capacity after END_STREAM."""
    import h2.settings

    ca = trustme.CA()
    cert = ca.issue_cert("localhost")
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.set_alpn_protocols(["h2"])
    cert.configure_cert(srv_ctx)
    cli_ctx = ssl.create_default_context()
    ca.configure_trust(cli_ctx)
    cli_ctx.set_alpn_protocols(["h2"])
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    first_seen = threading.Event()
    second_seen = threading.Event()
    finish_first = threading.Event()
    errors: queue.Queue[BaseException] = queue.Queue()

    def serve() -> None:
        first_id = 0
        first_done = False
        try:
            with listener:
                raw, _ = listener.accept()
                with srv_ctx.wrap_socket(raw, server_side=True) as sock:
                    sock.settimeout(0.05)
                    conn = h2.connection.H2Connection(
                        config=h2.config.H2Configuration(client_side=False)
                    )
                    conn.initiate_connection()
                    conn.update_settings(
                        {h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 1}
                    )
                    sock.sendall(conn.data_to_send())
                    deadline = time.monotonic() + 4
                    while time.monotonic() < deadline:
                        try:
                            buf = sock.recv(65535)
                        except TimeoutError:
                            buf = None
                        if buf == b"":
                            break
                        if buf:
                            for event in conn.receive_data(buf):
                                if isinstance(event, h2.events.RequestReceived):
                                    path = dict(event.headers)[b":path"]
                                    if path == b"/one":
                                        first_id = event.stream_id
                                        conn.send_headers(
                                            first_id, [(b":status", b"200")]
                                        )
                                        first_seen.set()
                                    elif path == b"/two":
                                        second_seen.set()
                                        conn.send_headers(
                                            event.stream_id, [(b":status", b"200")]
                                        )
                                        conn.send_data(
                                            event.stream_id, b"two", end_stream=True
                                        )
                        if finish_first.is_set() and not first_done and first_id:
                            conn.send_data(first_id, b"one", end_stream=True)
                            first_done = True
                        outgoing = conn.data_to_send()
                        if outgoing:
                            sock.sendall(outgoing)
                        if second_seen.is_set() and first_done:
                            return
        except Exception as exc:  # noqa: BLE001 - test relay
            errors.put(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    inject_into_urllib3()
    http = urllib3.PoolManager(
        maxsize=1, block=True, ssl_context=cli_ctx, retries=False
    )
    answers: queue.Queue[bytes | BaseException] = queue.Queue()

    def fetch_two() -> None:
        try:
            response = http.request("GET", f"https://localhost:{port}/two", timeout=3)
            answers.put(response.data)
        except Exception as exc:  # noqa: BLE001 - test relay
            answers.put(exc)

    try:
        first = http.request(
            "GET",
            f"https://localhost:{port}/one",
            preload_content=False,
            timeout=3,
        )
        assert first_seen.wait(2)
        t = threading.Thread(target=fetch_two, daemon=True)
        t.start()
        time.sleep(0.1)
        assert not second_seen.is_set(), "peer limit ignored"
        assert t.is_alive(), "second request did not wait for H2 stream capacity"
        finish_first.set()
        assert first.read() == b"one"
        first.close()
        t.join(4)
        assert not t.is_alive(), "capacity wait never woke after END_STREAM"
        assert list(answers.queue) == [b"two"], list(answers.queue)
        assert errors.empty(), list(errors.queue)
        pool = http.connection_from_host("localhost", port, scheme="https")
        assert pool.num_connections == 1
    finally:
        http.clear()
        extract_from_urllib3()
        finish_first.set()
        thread.join(2)


def test_pool_close_closes_shared_transport_and_pending_streams() -> None:
    """Closing a pool must close its H2 socket rather than only an empty queue."""
    from urllib3.http2.multiplex import HTTP2MultiplexConnectionPool, _Stream

    pool = HTTP2MultiplexConnectionPool("localhost")
    transport = pool._h2_transport
    sock = Mock()
    stream = _Stream(1, "/inflight", object())
    stream.chunks.append([b"queued", 6])
    with transport.condition:
        transport._sock = sock
        transport._streams[1] = stream
    pool.close()
    assert transport._closed is True
    assert transport.socket is None
    assert stream.error is not None
    assert not stream.chunks
    sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
    sock.close.assert_called_once()
    pool.close()  # idempotent
    sock.close.assert_called_once()


def test_ipv6_authority_is_bracketed() -> None:
    """An IPv6 literal needs brackets in an HTTP/2 :authority pseudoheader."""
    from types import SimpleNamespace

    from urllib3.http2.multiplex import _H2Transport

    transport = _H2Transport(SimpleNamespace(host="::1", port=8443))
    h2conn = Mock()
    h2conn.get_next_available_stream_id.return_value = 1
    h2conn.data_to_send.return_value = b""
    io = SimpleNamespace(h2=h2conn, sock=Mock(), closed=False, error=None, streams={})
    transport._session = io
    transport._h2 = h2conn
    transport._sock = io.sock
    transport._streams = io.streams
    transport.connect = lambda: None
    state = transport.open("GET", "/", {}, None)
    assert state.id == 1
    headers = dict(h2conn.send_headers.call_args.args[1])
    assert headers[b":authority"] == b"[::1]:8443"


def test_graceful_goaway_applies_minimum_last_stream_id() -> None:
    """Repeated GOAWAYs can decrease last_stream_id, never un-reject work."""
    from types import SimpleNamespace

    from hyperframe.frame import GoAwayFrame

    from urllib3.http2.multiplex import _H2Transport, _Session, _Stream

    transport = _H2Transport(SimpleNamespace(host="localhost", port=443))
    physical = SimpleNamespace(_h2_conn=SimpleNamespace(_obj=Mock()), sock=Mock())
    session = _Session(physical)
    transport._session = session
    transport._sessions.add(session)
    old = _Stream(1, "/old", session.h2)
    newer = _Stream(3, "/newer", session.h2)
    old.io = newer.io = session
    session.streams.update({1: old, 3: newer})
    with transport.condition:
        for last in (3, 1):
            frame = GoAwayFrame(0)
            frame.last_stream_id = last
            frame.error_code = 0
            transport._goaway(session, frame.serialize())
            if last == 3:
                assert newer.error is None
        assert old.error is None
        assert newer.error is not None
        assert session.goaway_last_stream_id == 1
        assert session.draining


def test_failed_tls_session_is_released_when_no_streams_are_live() -> None:
    """Repeated disconnects must not retain parser/socket state indefinitely."""
    from types import SimpleNamespace

    from urllib3.http2.multiplex import _H2Transport, _Session

    transport = _H2Transport(SimpleNamespace(host="localhost", port=443))
    sock = Mock()
    sock.recv.return_value = b""
    physical = SimpleNamespace(_h2_conn=SimpleNamespace(_obj=Mock()), sock=sock)
    session = _Session(physical)
    transport._session = session
    transport._sessions.add(session)
    transport._read_frames(session)
    assert session.error is not None
    assert session.closed
    assert session not in transport._sessions
    sock.close.assert_called_once()
