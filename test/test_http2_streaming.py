"""TLS H2 wire-level regression: real connection, two streams, bounded buffering."""

from __future__ import annotations

import hashlib
import socket
import ssl
import threading
import time
from queue import Queue

import h2.config
import h2.connection
import h2.events
import trustme

import urllib3
from urllib3.http2 import extract_from_urllib3, inject_into_urllib3

_PAYLOAD = bytes(range(256)) * 2048


def test_h2_flow_control_streaming_cancel_and_reuse() -> None:
    ca = trustme.CA()
    cert = ca.issue_cert("localhost")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.set_alpn_protocols(["h2"])
    cert.configure_cert(server_ctx)
    client_ctx = ssl.create_default_context()
    ca.configure_trust(client_ctx)
    client_ctx.set_alpn_protocols(["h2"])
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    stop = threading.Event()
    observations: Queue[tuple[str, object]] = Queue()
    saw_reset = threading.Event()

    def server() -> None:
        offsets: dict[int, int] = {}
        stalled_offsets: dict[int, int] = {}
        uploads: dict[int, object] = {}
        try:
            with listener:
                raw, _ = listener.accept()
                observations.put(("tcp", 1))
                with server_ctx.wrap_socket(raw, server_side=True) as sock:
                    sock.settimeout(0.15)
                    conn = h2.connection.H2Connection(
                        config=h2.config.H2Configuration(client_side=False)
                    )
                    conn.initiate_connection()
                    sock.sendall(conn.data_to_send())
                    while not stop.is_set():
                        try:
                            chunk = sock.recv(65535)
                        except TimeoutError:
                            chunk = None
                        if chunk == b"":
                            break
                        if chunk:
                            for event in conn.receive_data(chunk):
                                if isinstance(event, h2.events.RequestReceived):
                                    path = dict(event.headers)[b":path"]
                                    if path == b"/large":
                                        offsets[event.stream_id] = 0
                                        conn.send_headers(
                                            event.stream_id, [(b":status", b"200")]
                                        )
                                    elif path == b"/stall":
                                        stalled_offsets[event.stream_id] = 0
                                        conn.send_headers(
                                            event.stream_id, [(b":status", b"200")]
                                        )
                                    elif path == b"/upload":
                                        uploads[event.stream_id] = hashlib.sha256()
                                    else:
                                        conn.send_headers(
                                            event.stream_id, [(b":status", b"200")]
                                        )
                                        conn.send_data(
                                            event.stream_id, b"fast", end_stream=True
                                        )
                                elif isinstance(event, h2.events.DataReceived):
                                    digest = uploads.get(event.stream_id)
                                    if digest is not None:
                                        digest.update(event.data)
                                        conn.acknowledge_received_data(
                                            event.flow_controlled_length,
                                            event.stream_id,
                                        )
                                elif isinstance(event, h2.events.StreamEnded):
                                    digest = uploads.pop(event.stream_id, None)
                                    if digest is not None:
                                        conn.send_headers(
                                            event.stream_id, [(b":status", b"200")]
                                        )
                                        conn.send_data(
                                            event.stream_id,
                                            digest.hexdigest().encode(),
                                            end_stream=True,
                                        )
                                elif isinstance(event, h2.events.StreamReset):
                                    stalled_offsets.pop(event.stream_id, None)
                                    observations.put(("reset", event.stream_id))
                                    saw_reset.set()
                        for sid in list(stalled_offsets):
                            while stalled_offsets[sid] < 49152:
                                available = min(
                                    conn.local_flow_control_window(sid),
                                    conn.max_outbound_frame_size,
                                    49152 - stalled_offsets[sid],
                                )
                                if not available:
                                    break
                                conn.send_data(sid, b"X" * available)
                                stalled_offsets[sid] += available
                        for sid in list(offsets):
                            while offsets[sid] < len(_PAYLOAD):
                                available = min(
                                    conn.local_flow_control_window(sid),
                                    conn.max_outbound_frame_size,
                                    len(_PAYLOAD) - offsets[sid],
                                )
                                if not available:
                                    break
                                conn.send_data(
                                    sid,
                                    _PAYLOAD[offsets[sid] : offsets[sid] + available],
                                )
                                offsets[sid] += available
                            if offsets[sid] == len(_PAYLOAD):
                                conn.end_stream(sid)
                                del offsets[sid]
                        pending = conn.data_to_send()
                        if pending:
                            sock.sendall(pending)
        except Exception as exc:  # noqa: BLE001 - test thread must relay errors
            if not stop.is_set():
                observations.put(("error", repr(exc)))

    receiver = threading.Thread(target=server, daemon=True)
    receiver.start()
    inject_into_urllib3()
    http = urllib3.PoolManager(
        maxsize=1, block=True, retries=False, ssl_context=client_ctx
    )
    try:
        start = time.monotonic()
        response = http.request(
            "GET", f"https://localhost:{port}/large", preload_content=False, timeout=5
        )
        assert (
            time.monotonic() - start < 2
        ), "headers were delayed until body completion"
        chunks = list(response.stream(1024))
        assert len(chunks) >= 512
        assert max(map(len, chunks)) <= 1024
        assert b"".join(chunks) == _PAYLOAD
        response.close()
        # Four RST_STREAM cancellations each abandon 48 KiB of buffered DATA.
        # If the client forgets to restore connection-level flow credit,
        # subsequent requests on the same TCP connection deadlock.
        for _ in range(4):
            stalled = http.request(
                "GET",
                f"https://localhost:{port}/stall",
                preload_content=False,
                timeout=5,
            )
            assert stalled.read(100) == b"X" * 100
            # A stalled stream must not monopolize the TLS socket.
            fast = http.request("GET", f"https://localhost:{port}/fast", timeout=5)
            assert fast.data == b"fast"
            time.sleep(0.03)
            stalled.close()

        replayed = http.request("GET", f"https://localhost:{port}/large", timeout=5)
        assert replayed.data == _PAYLOAD
        payload = bytes(range(256)) * 1024
        uploaded = http.request(
            "POST", f"https://localhost:{port}/upload", body=payload, timeout=5
        )
        assert uploaded.data == hashlib.sha256(payload).hexdigest().encode()
        pool = http.connection_from_host("localhost", port, scheme="https")
        assert pool.num_connections == 1, "requests opened a second TCP connection"
        assert saw_reset.wait(2), "peer did not observe RST_STREAM"
        got = list(observations.queue)
        assert ("tcp", 1) in got, got
        assert sum(kind == "reset" for kind, _ in got) >= 4, got
        assert not any(kind == "error" for kind, _ in got), got
    finally:
        http.clear()
        extract_from_urllib3()
        stop.set()
        receiver.join(3)
