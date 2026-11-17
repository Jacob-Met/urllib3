from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from urllib3 import HTTPConnectionPool, PoolManager, Retry
from urllib3.exceptions import UnrewindableBodyError


@pytest.fixture
def upload_server() -> Iterator[tuple[str, list[tuple[str, bytes]]]]:
    received: list[tuple[str, bytes]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            pass

        def do_PUT(self) -> None:
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                data = bytearray()
                while size := int(self.rfile.readline().split(b";", 1)[0], 16):
                    data.extend(self.rfile.read(size))
                    self.rfile.read(2)
                self.rfile.readline()
                body = bytes(data)
            else:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))

            received.append((self.path, body))
            if self.path == "/status" and len(received) == 1:
                status, location = 503, None
            elif self.path.startswith("/crossredirect"):
                status = int(self.path.removeprefix("/crossredirect"))
                location = f"http://127.0.0.1:{other_server.server_port}/final"
            elif self.path.startswith("/redirect"):
                status = int(self.path.removeprefix("/redirect"))
                location = "/final"
            else:
                status, location = 200, None
            self.send_response(status)
            self.send_header("Content-Length", "0")
            if location is not None:
                self.send_header("Location", location)
            self.end_headers()

        def do_GET(self) -> None:
            received.append((self.path, b""))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    other_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    other_thread = threading.Thread(
        target=other_server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    other_thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", received
    finally:
        server.shutdown()
        other_server.shutdown()
        server.server_close()
        other_server.server_close()
        thread.join()
        other_thread.join()


@pytest.mark.parametrize("client_type", ["pool", "manager"])
@pytest.mark.parametrize("route", ["/status", "/redirect307", "/redirect308"])
@pytest.mark.parametrize(
    "make_body",
    [
        iter,
        lambda chunks: (chunk for chunk in chunks),
        lambda chunks: map(bytes, chunks),
    ],
)
def test_one_shot_iterator_is_not_silently_replayed(
    upload_server: tuple[str, list[tuple[str, bytes]]],
    client_type: str,
    route: str,
    make_body: Callable[[list[bytes]], Iterator[bytes]],
) -> None:
    url, received = upload_server
    retries = Retry(total=1, status=1, status_forcelist=[503], allowed_methods={"PUT"})
    with (
        PoolManager()
        if client_type == "manager"
        else HTTPConnectionPool("127.0.0.1", int(url.rsplit(":", 1)[1]))
    ) as client:
        with pytest.raises(UnrewindableBodyError):
            client.request(
                "PUT",
                url + route if client_type == "manager" else route,
                body=make_body([b"alpha", b"beta"]),
                retries=retries,
            )
    assert received == [(route, b"alphabeta")]


@pytest.mark.parametrize("client_type", ["pool", "manager"])
@pytest.mark.parametrize("route", ["/status", "/redirect307", "/redirect308"])
def test_reiterable_chunks_can_retry(
    upload_server: tuple[str, list[tuple[str, bytes]]],
    client_type: str,
    route: str,
) -> None:
    url, received = upload_server
    retries = Retry(total=1, status=1, status_forcelist=[503], allowed_methods={"PUT"})
    with (
        PoolManager()
        if client_type == "manager"
        else HTTPConnectionPool("127.0.0.1", int(url.rsplit(":", 1)[1]))
    ) as client:
        response = client.request(
            "PUT",
            url + route if client_type == "manager" else route,
            body=[b"alpha", b"beta"],
            retries=retries,
        )
    assert response.status == 200
    assert received == [
        (route, b"alphabeta"),
        ("/final" if route.startswith("/redirect") else route, b"alphabeta"),
    ]


@pytest.mark.parametrize("client_type", ["pool", "manager"])
def test_303_drops_iterator_body_without_rewinding(
    upload_server: tuple[str, list[tuple[str, bytes]]], client_type: str
) -> None:
    url, received = upload_server
    with (
        PoolManager()
        if client_type == "manager"
        else HTTPConnectionPool("127.0.0.1", int(url.rsplit(":", 1)[1]))
    ) as client:
        response = client.request(
            "PUT",
            url + "/redirect303" if client_type == "manager" else "/redirect303",
            body=iter([b"alpha", b"beta"]),
        )
    assert response.status == 200
    assert received == [("/redirect303", b"alphabeta"), ("/final", b"")]


@pytest.mark.parametrize("status", [307, 308])
def test_manager_cross_origin_redirect_refuses_one_shot_iterator(
    upload_server: tuple[str, list[tuple[str, bytes]]], status: int
) -> None:
    url, received = upload_server
    with PoolManager() as client:
        with pytest.raises(UnrewindableBodyError):
            client.request(
                "PUT",
                f"{url}/crossredirect{status}",
                body=iter([b"alpha", b"beta"]),
            )
    assert received == [(f"/crossredirect{status}", b"alphabeta")]
