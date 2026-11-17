"""HTTP/2 virtual-stream pool backed by one flow-controlled TLS connection.

This module is used only by the explicit HTTP/2 opt-in. A connection checked
out from the pool is a *stream*, not the underlying TCP/TLS connection.
"""

from __future__ import annotations

import collections
import io
import select
import socket
import ssl
import threading
import time
import typing
from collections.abc import Iterator

import h2.events
import h2.exceptions

from .._collections import HTTPHeaderDict
from ..connectionpool import HTTPSConnectionPool
from ..exceptions import ProtocolError, ReadTimeoutError
from ..response import BaseHTTPResponse
from .connection import (
    HTTP2Connection,
    _is_illegal_header_value,
    _is_legal_header_name,
)

_READ_SIZE = 65536


class _Stream:
    def __init__(self, identifier: int, url: str, session: typing.Any) -> None:
        self.id = identifier
        # Stream IDs are reusable after GOAWAY/reconnect. Ownership belongs
        # to the exact protocol session, never just its numeric stream ID.
        self.session = session
        self.url = url
        self.method = "GET"
        self.received_bytes = 0
        self.stream_credit_pending = 0
        self.status: int | None = None
        self.headers = HTTPHeaderDict()
        self.chunks: collections.deque[list[typing.Any]] = collections.deque()
        self.ended = False
        self.error: BaseException | None = None
        self.retired = False
        self.io: _Session | None = None


class _Session:
    """One TLS socket, its own H2 parser, and its own stream ID namespace."""

    def __init__(self, physical: HTTP2Connection) -> None:
        self.physical = physical
        self.h2 = physical._h2_conn._obj
        self.sock = physical.sock
        # An SSL connection is one stateful cipher, not independently
        # thread-safe read/write endpoints. Serialize SSL_read and SSL_write.
        self.io_lock = threading.Lock()
        self.streams: dict[int, _Stream] = {}
        self.inbound = bytearray()
        self.draining = False
        self.goaway_last_stream_id = 0x7FFFFFFF
        self.error: BaseException | None = None
        self.closed = False

    def frames(self, data: bytes) -> Iterator[bytes]:
        """Reassemble wire frames so graceful GOAWAY does not close hyper-h2.

        hyper-h2 4.x transitions directly to CLOSED on GOAWAY and rejects
        subsequent DATA for preexisting streams, contrary to RFC 9113 §6.8.
        We surface GOAWAY at the transport level while keeping the session's
        parser alive for its already-accepted streams.
        """
        self.inbound.extend(data)
        while len(self.inbound) >= 9:
            length = int.from_bytes(self.inbound[:3], "big")
            if length > self.h2.max_inbound_frame_size:
                raise ProtocolError("HTTP/2 peer sent an oversized frame")
            total = 9 + length
            if len(self.inbound) < total:
                return
            wire = bytes(self.inbound[:total])
            del self.inbound[:total]
            yield wire


class _H2Transport:
    def __init__(self, pool: HTTP2MultiplexConnectionPool) -> None:
        self.pool = pool
        self._connect_lock = threading.Lock()
        self.condition = threading.Condition(threading.RLock())
        self._physical: HTTP2Connection | None = None
        self._h2: typing.Any = None
        self._sock: typing.Any = None
        self._streams: dict[int, _Stream] = {}
        self._error: BaseException | None = None
        self._closed = False
        self._session: _Session | None = None
        self._sessions: set[_Session] = set()

    def connect(self) -> None:
        with self._connect_lock:
            with self.condition:
                if self._closed:
                    raise ProtocolError("HTTP/2 pool is closed")
                if self._sock is not None and self._error is None:
                    return
            # The stock HTTPSConnection implements all certificate, ALPN, proxy,
            # fingerprint, client-cert, hostname, and socket-option handling.
            physical = self.pool._new_conn()
            assert isinstance(physical, HTTP2Connection)
            physical.connect()
            try:
                tls_sock = typing.cast(ssl.SSLSocket, physical.sock)
                if tls_sock.selected_alpn_protocol() != "h2":
                    raise ProtocolError("TLS peer did not negotiate HTTP/2")
            except BaseException:
                physical.close()
                raise
            with self.condition:
                if self._closed:
                    physical.close()
                    raise ProtocolError("HTTP/2 pool is closed")
                session = _Session(physical)
                self._session = session
                self._sessions.add(session)
                self._physical = physical
                self._h2 = session.h2
                self._sock = session.sock
                self._sock.settimeout(0.25)
                self._error = None
                self._streams = session.streams
            threading.Thread(
                target=self._read_frames,
                args=(session,),
                name="urllib3-h2-receiver",
                daemon=True,
            ).start()

    @property
    def socket(self) -> typing.Any:
        return self._sock

    @property
    def verified(self) -> bool:
        return bool(self._physical and self._physical.is_verified)

    def _send_pending(self, session: _Session | None = None) -> None:
        """Call with the protocol lock held; never let frames overtake others."""
        if session is None:
            session = self._session
        if session is None or session.closed or session.error is not None:
            return
        wire = session.h2.data_to_send()
        if wire:
            with session.io_lock:
                session.sock.sendall(wire)

    def _goaway(self, session: _Session, frame: bytes) -> None:
        if len(frame) < 17 or frame[5:9] != b"\x00" * 4:
            raise ProtocolError("Invalid HTTP/2 GOAWAY frame")
        last_stream_id = int.from_bytes(frame[9:13], "big") & 0x7FFFFFFF
        error_code = int.from_bytes(frame[13:17], "big")
        if error_code:
            raise ProtocolError(f"HTTP/2 GOAWAY error ({error_code})")
        session.draining = True
        session.goaway_last_stream_id = min(
            session.goaway_last_stream_id, last_stream_id
        )
        if session is self._session:
            # New requests must establish fresh TLS; old streams keep reading
            # their own session, parser and flow-control windows independently.
            self._error = ProtocolError("HTTP/2 peer sent graceful GOAWAY")
        for stream in session.streams.values():
            if stream.id > session.goaway_last_stream_id and not stream.ended:
                stream.error = ProtocolError("HTTP/2 stream rejected by GOAWAY")
        self.condition.notify_all()

    def _release_if_drained(self, session: _Session) -> None:
        # Called with the condition held. Keep a GOAWAY'd session alive until
        # all accepted streams have been consumed/retired; then release both
        # its TLS socket and parser instead of accumulating old connections.
        if (
            not (session.draining or session.error is not None)
            or session.closed
            or session.streams
        ):
            return
        session.closed = True
        session.inbound.clear()
        self._sessions.discard(session)
        try:
            session.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        session.sock.close()

    def open(
        self,
        method: str,
        url: str,
        headers: typing.Mapping[str, str],
        body: typing.Any,
        timeout: float | None = None,
    ) -> _Stream:
        self.connect()
        with self.condition:
            self._check_session()
            host = self.pool.host
            authority = (
                f"[{host}]" if ":" in host and not host.startswith("[") else host
            )
            header_list = [
                (b":scheme", b"https"),
                (b":method", method.encode("ascii")),
                (
                    b":authority",
                    f"{authority}:{self.pool.port or 443}".encode("ascii"),
                ),
                (b":path", (url or "/").encode("ascii")),
            ]
            has_user_agent = False
            for name, value in headers.items():
                header_name = name.lower().encode("ascii")
                if header_name == b"transfer-encoding":
                    continue
                header_value = (
                    value.encode("latin-1") if isinstance(value, str) else value
                )
                if not _is_legal_header_name(header_name):
                    raise ValueError(f"Illegal HTTP/2 header name {name!r}")
                if _is_illegal_header_value(header_value):
                    raise ValueError(f"Illegal HTTP/2 header value for {name!r}")
                if header_name == b"user-agent":
                    has_user_agent = True
                header_list.append((header_name, header_value))
            if not has_user_agent:
                from ..connection import _get_default_user_agent

                header_list.append((b"user-agent", _get_default_user_agent().encode()))
            # SETTINGS_MAX_CONCURRENT_STREAMS is dynamic and applies to the
            # *physical* connection, not the number of borrowed pool slots.
            # hyper-h2 enforces the peer limit by raising TooManyStreamsError.
            # A completed/reset stream releases capacity: wait on the shared
            # receiver condition, rather than sending a prohibited stream or
            # opening one TLS connection per request.
            deadline = None if timeout is None else time.monotonic() + timeout
            while True:
                self._check_session()
                stream_id = self._h2.get_next_available_stream_id()
                try:
                    self._h2.send_headers(
                        stream_id, header_list, end_stream=body is None
                    )
                except h2.exceptions.TooManyStreamsError:
                    remaining = (
                        None if deadline is None else deadline - time.monotonic()
                    )
                    if remaining is not None and remaining <= 0:
                        raise ReadTimeoutError(
                            self.pool,
                            url,
                            "Timed out waiting for peer HTTP/2 stream capacity",
                        )
                    self.condition.wait(remaining)
                else:
                    break
            state = _Stream(stream_id, url, self._h2)
            state.io = self._session
            state.method = method.upper()
            self._streams[stream_id] = state
            self._send_pending()
            self.condition.notify_all()
        if body is not None:
            try:
                self.send_body(state, body)
            except BaseException:
                self.retire(state)
                raise
        return state

    def _check_session(self) -> None:
        if self._error is not None:
            raise ProtocolError("HTTP/2 session lost", self._error)
        if self._closed or self._sock is None:
            raise ProtocolError("HTTP/2 session closed")

    def send_body(self, state: _Stream, body: typing.Any) -> None:
        # A GOAWAY allows already accepted uploads to finish while new
        # requests go to a new TLS session. Never use the current session's
        # outbound flow-control windows for an old stream ID.
        session = state.io
        if session is None:
            raise ProtocolError("HTTP/2 upload has no owning session")
        if isinstance(body, str):
            body = body.encode()
        if isinstance(body, (bytes, bytearray, memoryview)):
            parts: typing.Iterable[bytes] = [bytes(body)]
        elif hasattr(body, "read"):

            def file_chunks() -> Iterator[bytes]:
                while True:
                    data = body.read(16384)
                    if not data:
                        break
                    yield data.encode() if isinstance(data, str) else bytes(data)

            parts = file_chunks()
        else:
            parts = body
        for chunk in parts:
            if isinstance(chunk, str):
                chunk = chunk.encode()
            pos = 0
            while pos < len(chunk):
                with self.condition:
                    if self._closed or session.closed or session.error is not None:
                        raise ProtocolError("HTTP/2 upload's session was lost")
                    if state.error is not None:
                        raise ProtocolError("HTTP/2 upload terminated", state.error)
                    credit = min(
                        session.h2.local_flow_control_window(state.id),
                        session.h2.max_outbound_frame_size,
                        len(chunk) - pos,
                    )
                    if credit == 0:
                        self.condition.wait(0.1)
                        continue
                    session.h2.send_data(state.id, chunk[pos : pos + credit])
                    self._send_pending(session)
                pos += credit
        with self.condition:
            if self._closed or session.closed or session.error is not None:
                raise ProtocolError("HTTP/2 upload's session was lost")
            if state.error is not None:
                raise ProtocolError("HTTP/2 upload terminated", state.error)
            session.h2.end_stream(state.id)
            self._send_pending(session)

    def _read_frames(self, session: _Session) -> None:
        sock = session.sock
        try:
            while True:
                with self.condition:
                    if self._closed or session.closed or session.error is not None:
                        return
                try:
                    # Do not hold the cipher lock while waiting for network
                    # readiness: outbound streams must remain responsive.
                    with session.io_lock:
                        pending = getattr(sock, "pending", lambda: 0)()
                    if not pending:
                        readable, _, _ = select.select([sock], [], [], 0.25)
                        if not readable:
                            continue
                    with session.io_lock:
                        received = sock.recv(_READ_SIZE)
                except TimeoutError:
                    continue
                if not received:
                    raise ProtocolError(
                        "HTTP/2 peer closed the connection before END_STREAM"
                    )
                with self.condition:
                    for frame in session.frames(received):
                        if frame[3] == 7:  # GOAWAY, handled without closing h2
                            self._goaway(session, frame)
                            continue
                        for event in session.h2.receive_data(frame):
                            self._handle_event(session, event)
                    self._send_pending(session)
                    self._release_if_drained(session)
                    self.condition.notify_all()
        except Exception as exc:  # noqa: BLE001
            with self.condition:
                session.error = exc
                if session is self._session:
                    self._error = exc
                for stream in session.streams.values():
                    if not stream.ended:
                        stream.error = exc
                self._release_if_drained(session)
                self.condition.notify_all()
            if not session.closed:
                try:
                    sock.close()
                except OSError:
                    pass

    def _handle_event(self, session: _Session, event: typing.Any) -> None:
        stream_id = getattr(event, "stream_id", None)
        state = session.streams.get(stream_id) if isinstance(stream_id, int) else None
        if isinstance(event, h2.events.ResponseReceived) and state:
            for name, value in event.headers:
                if name == b":status":
                    state.status = int(value)
                else:
                    state.headers.add(name.decode("ascii"), value.decode("latin-1"))
        elif isinstance(event, h2.events.DataReceived):
            # Restore connection credit when the frame arrives, independently
            # of application reads. Otherwise one unread stream can exhaust
            # the shared connection window and stall every other stream.
            # Stream credit remains consumption-driven to bound buffering.
            if event.flow_controlled_length:
                session.h2.increment_flow_control_window(event.flow_controlled_length)
            if state and not state.retired:
                state.received_bytes += len(event.data)
                state.chunks.append([event.data, event.flow_controlled_length])
        elif isinstance(event, h2.events.StreamEnded) and state:
            state.ended = True
            length = state.headers.get("content-length")
            if (
                length is not None
                and state.method != "HEAD"
                and state.status not in (204, 304)
            ):
                try:
                    expected = int(length)
                except ValueError:
                    state.error = ProtocolError("Invalid HTTP/2 Content-Length")
                else:
                    if expected != state.received_bytes:
                        state.error = ProtocolError(
                            f"HTTP/2 Content-Length {expected} differs from "
                            f"received body length {state.received_bytes}"
                        )
        elif isinstance(event, h2.events.StreamReset) and state:
            state.error = ProtocolError(
                f"HTTP/2 stream {event.stream_id} reset ({event.error_code})"
            )
            state.ended = True

    def wait_headers(self, state: _Stream, timeout: float | None) -> None:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self.condition:
            while state.status is None:
                self._raise_stream_error(state)
                self._wait(state, deadline)

    def _raise_stream_error(self, state: _Stream) -> None:
        if state.error is not None:
            raise ProtocolError(f"HTTP/2 stream {state.id} terminated", state.error)
        if state.retired:
            raise ProtocolError(f"HTTP/2 stream {state.id} retired")
        if state.ended and state.status is None:
            raise ProtocolError(
                f"HTTP/2 stream {state.id} ended before response headers"
            )

    def _wait(self, state: _Stream, deadline: float | None) -> None:
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise ReadTimeoutError(
                self.pool, state.url, "Timed out waiting for HTTP/2 stream data"
            )
        self.condition.wait(remaining)

    def receive(
        self, state: _Stream, amount: int | None, timeout: float | None
    ) -> bytes:
        if amount is not None and amount < 0:
            amount = None
        if amount == 0:
            return b""
        deadline = None if timeout is None else time.monotonic() + timeout
        collected: list[bytes] = []
        size = 0
        with self.condition:
            while amount is None or size < amount:
                if not state.chunks:
                    self._raise_stream_error(state)
                    if state.ended:
                        break
                    if size and amount is not None:
                        # read(amt) returns when enough arrives, not on every frame
                        pass
                    self._wait(state, deadline)
                    continue
                data, frame_credit = state.chunks[0]
                count = len(data) if amount is None else min(len(data), amount - size)
                collected.append(data[:count])
                size += count
                if count == len(data):
                    state.chunks.popleft()
                    credit = frame_credit
                else:
                    state.chunks[0] = [data[count:], frame_credit - count]
                    credit = count
                if (
                    credit
                    and not state.retired
                    and state.io is not None
                    and state.io.error is None
                    and not state.io.closed
                    and not self._closed
                    and not state.ended
                ):
                    state.stream_credit_pending += credit
                    if state.stream_credit_pending >= 16384:
                        state.io.h2.increment_flow_control_window(
                            state.stream_credit_pending, state.id
                        )
                        state.stream_credit_pending = 0
                        self._send_pending(state.io)
            # GOAWAY permits the same numeric ID on a *new* TLS session.
            if (
                state.ended
                and not state.chunks
                and state.io is not None
                and state.io.streams.get(state.id) is state
            ):
                state.io.streams.pop(state.id, None)
                self._release_if_drained(state.io)
        return b"".join(collected)

    def retire(self, state: _Stream) -> None:
        with self.condition:
            if state.retired:
                return
            state.retired = True
            if state.io is not None and state.io.streams.get(state.id) is state:
                state.io.streams.pop(state.id, None)
            if (
                state.io is not None
                and state.io.error is None
                and not state.io.closed
                and not self._closed
            ):
                # Connection window credit has already been restored when
                # DATA arrived. Discard stream-only credit on cancellation.
                if not state.ended:
                    try:
                        state.io.h2.reset_stream(state.id)
                    except h2.exceptions.H2Error:
                        pass
                try:
                    self._send_pending(state.io)
                except OSError:
                    pass
            state.chunks.clear()
            if state.io is not None:
                self._release_if_drained(state.io)
            self.condition.notify_all()

    def close(self) -> None:
        with self.condition:
            if self._closed:
                return
            self._closed = True
            sessions = list(self._sessions)
            sockets = [session.sock for session in sessions]
            # Also close a socket injected by a non-network test fixture.
            if self._session is None and self._sock is not None:
                sockets.append(self._sock)
            for session in sessions:
                session.closed = True
                for stream in session.streams.values():
                    stream.error = ProtocolError("HTTP/2 pool closed")
                    stream.chunks.clear()
                session.streams.clear()
            if self._session is None:
                for state in self._streams.values():
                    state.error = ProtocolError("HTTP/2 pool closed")
                    state.chunks.clear()
            self._streams.clear()
            self._sessions.clear()
            self._session = None
            self._physical = None
            self._sock = None
            self._h2 = None
            self.condition.notify_all()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


class HTTP2StreamResponse(BaseHTTPResponse):
    def __init__(
        self,
        state: _Stream,
        transport: _H2Transport,
        timeout: float | None,
        decode_content: bool,
    ) -> None:
        super().__init__(
            status=typing.cast(int, state.status),
            headers=state.headers,
            version=20,
            version_string="HTTP/2",
            reason=None,
            decode_content=decode_content,
            request_url=state.url,
        )
        self._state = state
        self._transport = transport
        self._timeout = timeout
        self._content: bytes | None = None
        self._read_position = 0
        self._decoded_pending = bytearray()
        self._decoded_flushed = False
        self._connection: HTTP2StreamConnection | None = None
        self._pool: HTTP2MultiplexConnectionPool | None = None
        self.length_remaining: int | None = None

    @property
    def url(self) -> str:
        return self._state.url

    @url.setter
    def url(self, url: str) -> None:
        self._state.url = url

    @property
    def data(self) -> bytes:
        if self._content is None:
            self._content = self.read()
        return self._content

    def _read_decoded(self, amount: int | None) -> bytes:
        # Reuse urllib3's own ContentDecoder abstraction, including its
        # bounded max_length / has_unconsumed_tail for gzip, deflate, brotli
        # and zstd. Never expand a compressed frame into unbounded data when
        # a caller requests a bounded stream chunk.
        self._init_decoder()
        if self._decoder is None:
            return self._transport.receive(self._state, amount, self._timeout)
        if amount is None:
            chunks = [bytes(self._decoded_pending)]
            self._decoded_pending.clear()
            if not self._decoded_flushed:
                if self._decoder.has_unconsumed_tail:
                    chunks.append(self._decode(b"", True, False))
                raw = self._transport.receive(self._state, None, self._timeout)
                chunks.append(self._decode(raw, True, True))
                self._decoded_flushed = True
            return b"".join(chunks)

        while len(self._decoded_pending) < amount and not self._decoded_flushed:
            available = amount - len(self._decoded_pending)
            if self._decoder.has_unconsumed_tail:
                decoded = self._decode(b"", True, False, max_length=available)
            else:
                # Reading compressed input in 16 KiB increments avoids huge
                # upstream buffers, while max_length bounds decoded output.
                raw = self._transport.receive(
                    self._state, min(16384, max(available, 1024)), self._timeout
                )
                if raw:
                    decoded = self._decode(raw, True, False, max_length=available)
                else:
                    decoded = self._decode(b"", True, True)
                    self._decoded_flushed = True
            self._decoded_pending.extend(decoded)
        result = bytes(self._decoded_pending[:amount])
        del self._decoded_pending[:amount]
        return result

    def read(
        self,
        amt: int | None = None,
        decode_content: bool | None = None,
        cache_content: bool = False,
    ) -> bytes:
        if amt is not None and amt < 0:
            amt = None
        if amt == 0:
            return b""
        if decode_content is None:
            decode_content = self.decode_content
        if self._content is not None:
            if amt is None:
                amount = len(self._content) - self._read_position
            else:
                amount = amt
            end = min(self._read_position + amount, len(self._content))
            part = self._content[self._read_position : end]
            self._read_position = end
            return part
        if decode_content:
            data = self._read_decoded(amt)
        else:
            # Do not allow a decoding-mode change after a decoder has produced
            # bytes; mirroring HTTPResponse's anti-corruption invariant.
            if self._has_decoded_content:
                raise RuntimeError(
                    "Calling read(decode_content=False) is not supported after "
                    "read(decode_content=True) was called."
                )
            data = self._transport.receive(self._state, amt, self._timeout)
        if cache_content or amt is None:
            self._content = data
            self._read_position = len(data)
        return data

    def read1(
        self, amt: int | None = None, decode_content: bool | None = None
    ) -> bytes:
        return self.read(amt, decode_content)

    def stream(
        self, amt: int | None = _READ_SIZE, decode_content: bool | None = None
    ) -> Iterator[bytes]:
        while chunk := self.read(amt, decode_content):
            yield chunk

    def read_chunked(
        self, amt: int | None = _READ_SIZE, decode_content: bool | None = None
    ) -> Iterator[bytes]:
        return self.stream(amt, decode_content)

    def get_redirect_location(self) -> str | None:
        if self.status in (301, 302, 303, 307, 308):
            return self.headers.get("location")
        return None

    def release_conn(self) -> None:
        if self._connection is not None:
            self._transport.retire(self._state)
            if self._pool is not None:
                self._pool._put_conn(self._connection)
            self._connection = None

    def drain_conn(self) -> None:
        for _ in self.stream():
            pass

    def shutdown(self) -> None:
        self.close()

    @property
    def connection(self) -> HTTP2StreamConnection | None:
        return self._connection

    def close(self) -> None:
        # BaseHTTPResponse.close() is deliberately abstract. Mark the IOBase
        # closed only after abandoning this virtual stream, not the shared TLS
        # connection that continues serving other concurrent requests.
        self._transport.retire(self._state)
        self.release_conn()
        io.IOBase.close(self)


class HTTP2StreamConnection(HTTP2Connection):
    def __init__(
        self, pool: HTTP2MultiplexConnectionPool, transport: _H2Transport
    ) -> None:
        super().__init__(pool.host, pool.port, timeout=pool.timeout.connect_timeout)
        self._transport = transport
        self._current: _Stream | None = None
        self._response_decode_content = True

    def connect(self) -> None:
        self._transport.connect()
        self.sock = self._transport.socket
        self.is_verified = self._transport.verified

    def request(
        self,
        method: str,
        url: str,
        body: typing.Any = None,
        headers: typing.Mapping[str, typing.Any] | None = None,
        **kwargs: typing.Any,
    ) -> None:
        self._response_decode_content = bool(kwargs.get("decode_content", True))
        self._current = self._transport.open(
            method, url, headers or {}, body, self.timeout
        )

    def getresponse(self) -> HTTP2StreamResponse:  # type: ignore[override]
        if self._current is None:
            raise ProtocolError("HTTP/2 getresponse without request")
        self._transport.wait_headers(self._current, self.timeout)
        return HTTP2StreamResponse(
            self._current, self._transport, self.timeout, self._response_decode_content
        )

    def close(self) -> None:
        if self._current is not None:
            self._transport.retire(self._current)
            self._current = None
        self.sock = None


class HTTP2MultiplexConnectionPool(HTTPSConnectionPool):
    """Each checked-out connection represents a virtual HTTP/2 stream."""

    ConnectionCls = HTTP2Connection

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        self._h2_transport = _H2Transport(self)

    def _get_conn(self, timeout: float | None = None) -> HTTP2Connection:
        # A CONNECT proxy sets up its tunnel on the *checked-out connection*
        # via the base pool's _prepare_proxy(). Preserve that path instead of
        # applying tunnel state to a virtual stream and bypassing proxy auth.
        if self.proxy is not None:
            return typing.cast(HTTP2Connection, super()._get_conn(timeout))
        return HTTP2StreamConnection(self, self._h2_transport)

    def _put_conn(self, conn: typing.Any) -> None:
        if self.proxy is not None:
            super()._put_conn(conn)
        elif conn is not None:
            conn.close()

    def _make_request(
        self, *args: typing.Any, **kwargs: typing.Any
    ) -> BaseHTTPResponse:
        preload = kwargs.get("preload_content", True)
        response = super()._make_request(*args, **kwargs)
        if preload:
            # ConnectionPool releases the virtual stream on function exit; the
            # body must already be consumed before the stream is recycled.
            _ = response.data
        return response

    def close(self) -> None:
        self._h2_transport.close()
        super().close()
