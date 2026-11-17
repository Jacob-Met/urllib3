"""A graceful HTTP/2 GOAWAY does not cancel accepted in-flight streams."""

from __future__ import annotations

import queue
import socket
import ssl
import threading
import time

import h2.config
import h2.connection
import h2.events
import hyperframe.frame
import pytest
import trustme

import urllib3
from urllib3.http2 import extract_from_urllib3, inject_into_urllib3


@pytest.mark.parametrize("split_goaway", [False, True])
def test_goaway_preserves_old_stream_while_new_tls_session_starts(
    split_goaway: bool,
) -> None:
    ca = trustme.CA()
    cert = ca.issue_cert("localhost")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.set_alpn_protocols(["h2"])
    cert.configure_cert(server_context)
    client_context = ssl.create_default_context()
    client_context.set_alpn_protocols(["h2"])
    ca.configure_trust(client_context)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(4)
    port = listener.getsockname()[1]
    first_accepted = threading.Event()
    goaway_sent = threading.Event()
    second_received = threading.Event()
    done = threading.Event()
    errors: queue.Queue[BaseException] = queue.Queue()

    def receive_request(sock: ssl.SSLSocket, server: h2.connection.H2Connection) -> int:
        until = time.monotonic() + 3
        while time.monotonic() < until:
            try:
                received = sock.recv(65535)
            except TimeoutError:
                continue
            if not received:
                break
            for event in server.receive_data(received):
                if isinstance(event, h2.events.RequestReceived):
                    return event.stream_id
        raise AssertionError("HTTP/2 peer did not send a request")

    def serve_first() -> None:
        try:
            with listener:
                raw, _ = listener.accept()
                first_accepted.set()
                with server_context.wrap_socket(raw, server_side=True) as sock:
                    sock.settimeout(0.1)
                    h2conn = h2.connection.H2Connection(
                        config=h2.config.H2Configuration(client_side=False)
                    )
                    h2conn.initiate_connection()
                    sock.sendall(h2conn.data_to_send())
                    stream = receive_request(sock, h2conn)
                    h2conn.send_headers(stream, [(b":status", b"200")])
                    goaway = hyperframe.frame.GoAwayFrame(0)
                    goaway.last_stream_id = stream
                    goaway.error_code = 0
                    # Deliberately send a raw GOAWAY before DATA. hyper-h2
                    # currently rejects further DATA after *its own* close_connection.
                    sock.sendall(h2conn.data_to_send())
                    wire = goaway.serialize()
                    if split_goaway:
                        for part in (wire[:5], wire[5:13], wire[13:]):
                            sock.sendall(part)
                    else:
                        sock.sendall(wire)
                    goaway_sent.set()
                    if not second_received.wait(3):
                        raise AssertionError(
                            "new TLS session did not start during old stream"
                        )
                    h2conn.send_data(stream, b"old-after-goaway", end_stream=True)
                    sock.sendall(h2conn.data_to_send())
                    done.wait(2)
        except Exception as exc:  # noqa: BLE001 - relay server-thread failures
            errors.put(exc)
            first_accepted.set()
            goaway_sent.set()
            second_received.set()

    def serve_second() -> None:
        try:
            if not first_accepted.wait(3):
                raise AssertionError("first TLS session was not accepted")
            raw, _ = listener.accept()
            with server_context.wrap_socket(raw, server_side=True) as sock:
                sock.settimeout(0.1)
                h2conn = h2.connection.H2Connection(
                    config=h2.config.H2Configuration(client_side=False)
                )
                h2conn.initiate_connection()
                sock.sendall(h2conn.data_to_send())
                stream = receive_request(sock, h2conn)
                h2conn.send_headers(stream, [(b":status", b"200")])
                h2conn.send_data(stream, b"fresh", end_stream=True)
                sock.sendall(h2conn.data_to_send())
                second_received.set()
                done.wait(2)
        except Exception as exc:  # noqa: BLE001 - relay server-thread failures
            errors.put(exc)
            second_received.set()

    threads = [
        threading.Thread(target=fn, daemon=True) for fn in (serve_first, serve_second)
    ]
    for thread in threads:
        thread.start()
    inject_into_urllib3()
    manager = urllib3.PoolManager(
        maxsize=1, block=True, retries=False, ssl_context=client_context
    )
    try:
        first = manager.request(
            "GET", f"https://localhost:{port}/old", preload_content=False, timeout=3
        )
        assert goaway_sent.wait(2), "graceful GOAWAY never sent"
        # The GOAWAY header may arrive across several TLS records. Wait for
        # the client receiver to observe it before opening a new stream.
        with first._transport.condition:
            assert first._transport.condition.wait_for(
                lambda: first._transport._error is not None, timeout=3
            ), "client did not receive GOAWAY"
        # The new request must progress even while the prior accepted stream is incomplete.
        second = manager.request("GET", f"https://localhost:{port}/new", timeout=3)
        assert second.data == b"fresh"
        # The client can finish reading before the server's sendall returns.
        assert second_received.wait(2)
        assert first.read() == b"old-after-goaway"
        old_session = first._state.io
        first.close()
        pool = manager.connection_from_host("localhost", port, scheme="https")
        assert pool.num_connections == 2
        assert old_session is not None and old_session.closed
        assert old_session not in pool._h2_transport._sessions
        assert len(pool._h2_transport._sessions) == 1
        assert errors.empty(), list(errors.queue)
    finally:
        done.set()
        second_received.set()
        manager.clear()
        extract_from_urllib3()
        for thread in threads:
            thread.join(2)
        listener.close()
