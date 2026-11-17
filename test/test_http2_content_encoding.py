"""Real TLS HTTP/2 regression for incremental decompression and raw bytes."""

from __future__ import annotations

import gzip
import queue
import socket
import ssl
import threading
import zlib

import h2.config
import h2.connection
import h2.events
import pytest
import trustme

import urllib3
from urllib3.exceptions import DecodeError
from urllib3.http2 import extract_from_urllib3, inject_into_urllib3

_BODY = bytes(range(256)) * 2048


def test_h2_compressed_streaming_raw_and_reuse() -> None:
    gzip_body = gzip.compress(_BODY)
    deflate_body = zlib.compress(_BODY)
    assert len(gzip_body) < 16384
    assert len(deflate_body) < 16384
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
    stopped = threading.Event()
    observed: queue.Queue[tuple[str, object]] = queue.Queue()

    def serve() -> None:
        try:
            with listener:
                raw, _ = listener.accept()
                observed.put(("tcp", 1))
                with server_context.wrap_socket(raw, server_side=True) as tls:
                    tls.settimeout(0.1)
                    h2conn = h2.connection.H2Connection(
                        config=h2.config.H2Configuration(client_side=False)
                    )
                    h2conn.initiate_connection()
                    tls.sendall(h2conn.data_to_send())
                    while not stopped.is_set():
                        try:
                            buf = tls.recv(65535)
                        except TimeoutError:
                            buf = None
                        if buf == b"":
                            return
                        if not buf:
                            continue
                        for event in h2conn.receive_data(buf):
                            if not isinstance(event, h2.events.RequestReceived):
                                continue
                            path = dict(event.headers)[b":path"]
                            if path in (b"/gzip", b"/gzip-raw"):
                                encoding, response = b"gzip", gzip_body
                            elif path == b"/deflate":
                                encoding, response = b"deflate", deflate_body
                            elif path == b"/invalid":
                                encoding, response = b"gzip", b"not a valid gzip"
                            else:
                                encoding, response = None, b"healthy"
                            hdrs = [
                                (b":status", b"200"),
                                (b"content-length", str(len(response)).encode()),
                            ]
                            if encoding:
                                hdrs.append((b"content-encoding", encoding))
                            h2conn.send_headers(event.stream_id, hdrs)
                            h2conn.send_data(event.stream_id, response, end_stream=True)
                            observed.put(("path", path.decode()))
                        out = h2conn.data_to_send()
                        if out:
                            tls.sendall(out)
        except Exception as exc:  # noqa: BLE001 - always report test thread errors
            if not stopped.is_set():
                observed.put(("error", repr(exc)))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    inject_into_urllib3()
    manager = urllib3.PoolManager(
        maxsize=1, block=True, ssl_context=client_context, retries=False
    )
    try:
        streamed = manager.request(
            "GET", f"https://localhost:{port}/gzip", preload_content=False, timeout=5
        )
        chunks = list(streamed.stream(1024))
        assert len(chunks) >= 512, "compressed response did not stream bounded bytes"
        assert max(map(len, chunks)) <= 1024
        assert b"".join(chunks) == _BODY
        streamed.close()
        assert streamed.closed, "HTTP/2 response must expose IOBase close state"

        raw = manager.request(
            "GET",
            f"https://localhost:{port}/gzip-raw",
            decode_content=False,
            timeout=5,
        )
        assert raw.data == gzip_body

        deflated = manager.request(
            "GET", f"https://localhost:{port}/deflate", timeout=5
        )
        assert deflated.data == _BODY

        invalid = manager.request(
            "GET", f"https://localhost:{port}/invalid", preload_content=False, timeout=5
        )
        try:
            with pytest.raises(DecodeError):
                invalid.read(1024)
        finally:
            invalid.close()

        healthy = manager.request("GET", f"https://localhost:{port}/healthy", timeout=5)
        assert healthy.data == b"healthy"
        pool = manager.connection_from_host("localhost", port, scheme="https")
        assert pool.num_connections == 1
        events = list(observed.queue)
        assert sum(e[0] == "tcp" for e in events) == 1, events
        assert sum(e[0] == "path" for e in events) == 5, events
        assert not any(e[0] == "error" for e in events), events
    finally:
        manager.clear()
        extract_from_urllib3()
        stopped.set()
        thread.join(2)
