"""HTTP/2 GOAWAY and TLS session rollover must not alias live stream state."""

from __future__ import annotations

import queue
import socket
import ssl
import threading
import time

import h2.config
import h2.connection
import h2.events
import pytest
import trustme

import urllib3
from urllib3.http2 import extract_from_urllib3, inject_into_urllib3

_FIRST_BODY = b"A" * 49152


@pytest.mark.parametrize("interrupted", [False, True])
def test_ended_stream_survives_goaway_and_new_tls_session(
    interrupted: bool,
) -> None:
    ca = trustme.CA()
    certificate = ca.issue_cert("localhost")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.set_alpn_protocols(["h2"])
    certificate.configure_cert(server_context)
    client_context = ssl.create_default_context()
    client_context.set_alpn_protocols(["h2"])
    ca.configure_trust(client_context)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    released = threading.Event()
    first_discarded = threading.Event()
    # The server cannot close TLS immediately after sendall(): doing so can
    # discard a peer-unread HTTP/2 DATA/END_STREAM flight on some platforms.
    # Hold the first TLS session until the client has parsed its GOAWAY.
    first_goaway_received = threading.Event()
    observed: queue.Queue[tuple[str, object]] = queue.Queue()

    def server() -> None:
        try:
            with listener:
                for session in range(2):
                    raw, _ = listener.accept()
                    observed.put(("tcp", session + 1))
                    with server_context.wrap_socket(raw, server_side=True) as sock:
                        sock.settimeout(0.1)
                        h2conn = h2.connection.H2Connection(
                            config=h2.config.H2Configuration(client_side=False)
                        )
                        h2conn.initiate_connection()
                        sock.sendall(h2conn.data_to_send())
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            try:
                                data = sock.recv(65535)
                            except TimeoutError:
                                continue
                            if data == b"":
                                break
                            requested = [
                                ev
                                for ev in h2conn.receive_data(data)
                                if isinstance(ev, h2.events.RequestReceived)
                            ]
                            if not requested:
                                continue
                            for ev in requested:
                                h2conn.send_headers(
                                    ev.stream_id, [(b":status", b"200")]
                                )
                                if interrupted and session == 0:
                                    continue  # GOAWAY interrupts stream 1 mid-response.
                                if interrupted and session == 1:
                                    # Deliver headers before the old response is
                                    # cancelled, so the new stream is still open.
                                    sock.sendall(h2conn.data_to_send())
                                    if not first_discarded.wait(2):
                                        raise AssertionError(
                                            "old-stream disposal blocked"
                                        )
                                body = _FIRST_BODY if session == 0 else b"second"
                                for offset in range(0, len(body), 16384):
                                    part = body[offset : offset + 16384]
                                    h2conn.send_data(
                                        ev.stream_id,
                                        part,
                                        end_stream=offset + len(part) == len(body),
                                    )
                            if session == 0:
                                h2conn.close_connection(error_code=0)
                            sock.sendall(h2conn.data_to_send())
                            if session == 0 and not first_goaway_received.wait(4):
                                raise AssertionError(
                                    "first GOAWAY not received by client"
                                )
                            if session == 1:
                                # Keep TLS alive until the client consumes the
                                # stream: closing with unread peer frames can
                                # otherwise trigger an unrelated TCP reset.
                                released.wait(2)
                            break
        except Exception as exc:  # noqa: BLE001 - test thread diagnostics
            observed.put(("error", repr(exc)))

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    inject_into_urllib3()
    manager = urllib3.PoolManager(
        maxsize=1, block=True, ssl_context=client_context, retries=False
    )
    try:
        first = manager.request(
            "GET", f"https://localhost:{port}/before", preload_content=False, timeout=3
        )
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with first._transport.condition:
                if (
                    first._state.ended or interrupted
                ) and first._transport._error is not None:
                    break
            time.sleep(0.005)
        else:
            raise AssertionError(
                f"server's graceful GOAWAY was not observed: "
                f"ended={first._state.ended}, "
                f"session_error={first._transport._error!r}, "
                f"peer_events={list(observed.queue)}"
            )

        first_goaway_received.set()
        second = manager.request(
            "GET",
            f"https://localhost:{port}/after",
            timeout=3,
            preload_content=not interrupted,
        )
        if interrupted:
            first.close()
            first_discarded.set()
            try:
                received = second.read()
            except Exception as exc:
                raise AssertionError(
                    f"new stream failed after old cancellation: {exc!r}; "
                    f"peer events={list(observed.queue)}; "
                    f"active streams={list(second._transport._streams)}; "
                    f"same_session={second._state.session is second._transport._h2}"
                ) from exc
            assert (
                received == b"second"
            ), "retiring an obsolete stream must not reset a new session's stream"
            second.close()
        else:
            assert second.data == b"second"
            assert (
                first.read() == _FIRST_BODY
            ), "old stream lost data on session rollover"
            first.close()
        pool = manager.connection_from_host("localhost", port, scheme="https")
        assert pool.num_connections == 2
        events = list(observed.queue)
        assert [v for k, v in events if k == "tcp"] == [1, 2]
        assert not any(kind == "error" for kind, _ in events), events
    finally:
        first_goaway_received.set()
        released.set()
        first_discarded.set()
        manager.clear()
        extract_from_urllib3()
        thread.join(2)
