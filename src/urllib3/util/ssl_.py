from __future__ import annotations

import hashlib
import hmac
import os
import socket
import stat
import struct
import sys
import threading
import time
import typing
import warnings
import weakref
from binascii import Error as BinasciiError
from binascii import unhexlify

from ..exceptions import ProxySchemeUnsupported, SSLError
from .url import _BRACELESS_IPV6_ADDRZ_RE, _IPV4_RE

SSLContext = None
SSLTransport = None
HAS_NEVER_CHECK_COMMON_NAME = False
IS_PYOPENSSL = False
ALPN_PROTOCOLS = ["http/1.1"]

# Only the first connection may configure a caller-provided SSLContext. OpenSSL
# doesn't allow changing an SSL_CTX after creating SSL objects from it, and
# multiple pool connections can be opened concurrently.
_SHARED_CONTEXT_LOCK = threading.Lock()
_SHARED_CONTEXT_CONFIGS: weakref.WeakKeyDictionary[
    typing.Any, tuple[typing.Any, ...]
] = weakref.WeakKeyDictionary()
# Directory metadata scans require one stat syscall per certificate. On Linux
# listen for mutations, with bounded rescans for missed/coalesced notifications;
# on other platforms retain the immediate metadata scan.
_CAPATH_WATCHERS: weakref.WeakValueDictionary[str, _CAPathWatcher] = (
    weakref.WeakValueDictionary()
)

_TYPE_VERSION_INFO = tuple[int, int, int, str, int]

# Maps the length of a digest to a possible hash function producing this digest
HASHFUNC_MAP = {
    length: getattr(hashlib, algorithm, None)
    for length, algorithm in ((32, "md5"), (40, "sha1"), (64, "sha256"))
}


def _is_has_never_check_common_name_reliable(
    openssl_version: str,
) -> bool:
    # As of May 2023, all released versions of LibreSSL fail to reject certificates with
    # only common names, see https://github.com/urllib3/urllib3/pull/3024
    is_openssl = openssl_version.startswith("OpenSSL ")

    return is_openssl


if typing.TYPE_CHECKING:
    from ssl import VerifyMode
    from typing import TypedDict

    from .ssltransport import SSLTransport as SSLTransportType

    class _TYPE_PEER_CERT_RET_DICT(TypedDict, total=False):
        subjectAltName: tuple[tuple[str, str], ...]
        subject: tuple[tuple[tuple[str, str], ...], ...]
        serialNumber: str


# Mapping from 'ssl.PROTOCOL_TLSX' to 'TLSVersion.X'
_SSL_VERSION_TO_TLS_VERSION: dict[int, int] = {}

try:  # Do we have ssl at all?
    import ssl
    from ssl import (  # type: ignore[assignment]
        CERT_REQUIRED,
        HAS_NEVER_CHECK_COMMON_NAME,
        OP_NO_COMPRESSION,
        OP_NO_TICKET,
        OPENSSL_VERSION,
        PROTOCOL_TLS,
        PROTOCOL_TLS_CLIENT,
        VERIFY_X509_PARTIAL_CHAIN,
        VERIFY_X509_STRICT,
        OP_NO_SSLv2,
        OP_NO_SSLv3,
        SSLContext,
        TLSVersion,
    )

    PROTOCOL_SSLv23 = PROTOCOL_TLS

    # Setting SSLContext.hostname_checks_common_name = False didn't work with
    # LibreSSL, check details in the used function.
    if HAS_NEVER_CHECK_COMMON_NAME and not _is_has_never_check_common_name_reliable(
        OPENSSL_VERSION,
    ):  # Defensive:
        HAS_NEVER_CHECK_COMMON_NAME = False

    # Need to be careful here in case old TLS versions get
    # removed in future 'ssl' module implementations.
    for attr in ("TLSv1", "TLSv1_1", "TLSv1_2"):
        try:
            _SSL_VERSION_TO_TLS_VERSION[getattr(ssl, f"PROTOCOL_{attr}")] = getattr(
                TLSVersion, attr
            )
        except AttributeError:  # Defensive:
            continue

    from .ssltransport import SSLTransport  # type: ignore[assignment]
except ImportError:
    OP_NO_COMPRESSION = 0x20000  # type: ignore[assignment,misc]
    OP_NO_TICKET = 0x4000  # type: ignore[assignment,misc]
    OP_NO_SSLv2 = 0x1000000  # type: ignore[assignment,misc]
    OP_NO_SSLv3 = 0x2000000  # type: ignore[assignment,misc]
    PROTOCOL_SSLv23 = PROTOCOL_TLS = 2  # type: ignore[assignment,misc]
    PROTOCOL_TLS_CLIENT = 16  # type: ignore[assignment,misc]
    VERIFY_X509_PARTIAL_CHAIN = 0x80000  # type: ignore[assignment,misc]
    VERIFY_X509_STRICT = 0x20  # type: ignore[assignment,misc]


_TYPE_PEER_CERT_RET = typing.Union["_TYPE_PEER_CERT_RET_DICT", bytes, None]


def assert_fingerprint(cert: bytes | None, fingerprint: str) -> None:
    """
    Checks if given fingerprint matches the supplied certificate.

    :param cert:
        Certificate as bytes object.
    :param fingerprint:
        Fingerprint as string of hexdigits, can be interspersed by colons.
    """

    if cert is None:
        raise SSLError("No certificate for the peer.")

    fingerprint = fingerprint.replace(":", "").lower()
    digest_length = len(fingerprint)
    if digest_length not in HASHFUNC_MAP:
        raise SSLError(f"Fingerprint of invalid length: {fingerprint}")
    hashfunc = HASHFUNC_MAP.get(digest_length)
    if hashfunc is None:
        raise SSLError(
            f"Hash function implementation unavailable for fingerprint length: {digest_length}"
        )

    # We need encode() here for py32; works on py2 and p33.
    try:
        fingerprint_bytes = unhexlify(fingerprint.encode())
    except BinasciiError as e:
        raise SSLError(e) from e

    cert_digest = hashfunc(cert).digest()

    if not hmac.compare_digest(cert_digest, fingerprint_bytes):
        raise SSLError(
            f'Fingerprints did not match. Expected "{fingerprint}", got "{cert_digest.hex()}"'
        )


def resolve_cert_reqs(candidate: None | int | str) -> VerifyMode:
    """
    Resolves the argument to a numeric constant, which can be passed to
    the wrap_socket function/method from the ssl module.
    Defaults to :data:`ssl.CERT_REQUIRED`.
    If given a string it is assumed to be the name of the constant in the
    :mod:`ssl` module or its abbreviation.
    (So you can specify `REQUIRED` instead of `CERT_REQUIRED`.
    If it's neither `None` nor a string we assume it is already the numeric
    constant which can directly be passed to wrap_socket.
    """
    if candidate is None:
        return CERT_REQUIRED

    if isinstance(candidate, str):
        res = getattr(ssl, candidate, None)
        if res is None:
            res = getattr(ssl, "CERT_" + candidate)
        return res  # type: ignore[no-any-return]

    return candidate  # type: ignore[return-value]


def resolve_ssl_version(candidate: None | int | str) -> int:
    """
    like resolve_cert_reqs
    """
    if candidate is None:
        return PROTOCOL_TLS

    if isinstance(candidate, str):
        res = getattr(ssl, candidate, None)
        if res is None:
            res = getattr(ssl, "PROTOCOL_" + candidate)
        return typing.cast(int, res)

    return candidate


def create_urllib3_context(
    ssl_version: int | None = None,
    cert_reqs: int | None = None,
    options: int | None = None,
    ciphers: str | None = None,
    ssl_minimum_version: int | None = None,
    ssl_maximum_version: int | None = None,
    verify_flags: int | None = None,
) -> ssl.SSLContext:
    """Creates and configures an :class:`ssl.SSLContext` instance for use with urllib3.

    :param ssl_version:
        The desired protocol version to use. This will default to
        PROTOCOL_SSLv23 which will negotiate the highest protocol that both
        the server and your installation of OpenSSL support.

        This parameter is deprecated instead use 'ssl_minimum_version'.
    :param ssl_minimum_version:
        The minimum version of TLS to be used. Use the 'ssl.TLSVersion' enum for specifying the value.
    :param ssl_maximum_version:
        The maximum version of TLS to be used. Use the 'ssl.TLSVersion' enum for specifying the value.
        Not recommended to set to anything other than 'ssl.TLSVersion.MAXIMUM_SUPPORTED' which is the
        default value.
    :param cert_reqs:
        Whether to require the certificate verification. This defaults to
        ``ssl.CERT_REQUIRED``.
    :param options:
        Specific OpenSSL options. These default to ``ssl.OP_NO_SSLv2``,
        ``ssl.OP_NO_SSLv3``, ``ssl.OP_NO_COMPRESSION``, and ``ssl.OP_NO_TICKET``.
    :param ciphers:
        Which cipher suites to allow the server to select. Defaults to either system configured
        ciphers if OpenSSL 1.1.1+, otherwise uses a secure default set of ciphers.
    :param verify_flags:
        The flags for certificate verification operations. These default to
        ``ssl.VERIFY_X509_PARTIAL_CHAIN`` and ``ssl.VERIFY_X509_STRICT`` for Python 3.13+.
    :returns:
        Constructed SSLContext object with specified options
    :rtype: SSLContext
    """
    if SSLContext is None:
        raise TypeError("Can't create an SSLContext object without an ssl module")

    # This means 'ssl_version' was specified as an exact value.
    if ssl_version not in (None, PROTOCOL_TLS, PROTOCOL_TLS_CLIENT):
        # Disallow setting 'ssl_version' and 'ssl_minimum|maximum_version'
        # to avoid conflicts.
        if ssl_minimum_version is not None or ssl_maximum_version is not None:
            raise ValueError(
                "Can't specify both 'ssl_version' and either "
                "'ssl_minimum_version' or 'ssl_maximum_version'"
            )

        # 'ssl_version' is deprecated and will be removed in the future.
        else:
            # Use 'ssl_minimum_version' and 'ssl_maximum_version' instead.
            ssl_minimum_version = _SSL_VERSION_TO_TLS_VERSION.get(
                ssl_version, TLSVersion.MINIMUM_SUPPORTED
            )
            ssl_maximum_version = _SSL_VERSION_TO_TLS_VERSION.get(
                ssl_version, TLSVersion.MAXIMUM_SUPPORTED
            )

            # This warning message is pushing users to use 'ssl_minimum_version'
            # instead of both min/max. Best practice is to only set the minimum version and
            # keep the maximum version to be it's default value: 'TLSVersion.MAXIMUM_SUPPORTED'
            warnings.warn(
                "'ssl_version' option is deprecated and will be "
                "removed in urllib3 v3.0. Instead use 'ssl_minimum_version'",
                category=FutureWarning,
                stacklevel=2,
            )

    context = SSLContext(PROTOCOL_TLS_CLIENT)
    if ssl_minimum_version is not None:
        context.minimum_version = ssl_minimum_version
    else:  # pyOpenSSL defaults to 'MINIMUM_SUPPORTED' so explicitly set TLSv1.2 here
        context.minimum_version = TLSVersion.TLSv1_2

    if ssl_maximum_version is not None:
        context.maximum_version = ssl_maximum_version

    # Unless we're given ciphers defer to either system ciphers in
    # the case of OpenSSL 1.1.1+ or use our own secure default ciphers.
    if ciphers:
        context.set_ciphers(ciphers)

    # Setting the default here, as we may have no ssl module on import
    cert_reqs = ssl.CERT_REQUIRED if cert_reqs is None else cert_reqs

    if options is None:
        options = 0
        # SSLv2 is easily broken and is considered harmful and dangerous
        options |= OP_NO_SSLv2
        # SSLv3 has several problems and is now dangerous
        options |= OP_NO_SSLv3
        # Disable compression to prevent CRIME attacks for OpenSSL 1.0+
        # (issue #309)
        options |= OP_NO_COMPRESSION
        # TLSv1.2 only. Unless set explicitly, do not request tickets.
        # This may save some bandwidth on wire, and although the ticket is encrypted,
        # there is a risk associated with it being on wire,
        # if the server is not rotating its ticketing keys properly.
        options |= OP_NO_TICKET

    context.options |= options

    if verify_flags is None:
        verify_flags = 0
        # In Python 3.13+ ssl.create_default_context() sets VERIFY_X509_PARTIAL_CHAIN
        # and VERIFY_X509_STRICT so we do the same
        if sys.version_info >= (3, 13):
            verify_flags |= VERIFY_X509_PARTIAL_CHAIN
            verify_flags |= VERIFY_X509_STRICT

    context.verify_flags |= verify_flags

    # Enable post-handshake authentication for TLS 1.3, see GH #1634. PHA is
    # necessary for conditional client cert authentication with TLS 1.3.
    # The attribute is None for OpenSSL <= 1.1.0 or does not exist when using
    # an SSLContext created by pyOpenSSL.
    if getattr(context, "post_handshake_auth", None) is not None:
        context.post_handshake_auth = True

    # The order of the below lines setting verify_mode and check_hostname
    # matter due to safe-guards SSLContext has to prevent an SSLContext with
    # check_hostname=True, verify_mode=NONE/OPTIONAL.
    # We always set 'check_hostname=False' for pyOpenSSL so we rely on our own
    # 'ssl.match_hostname()' implementation.
    if cert_reqs == ssl.CERT_REQUIRED and not IS_PYOPENSSL:
        context.verify_mode = cert_reqs
        context.check_hostname = True
    else:
        context.check_hostname = False
        context.verify_mode = cert_reqs

    context.hostname_checks_common_name = False

    if "SSLKEYLOGFILE" in os.environ:
        sslkeylogfile = os.path.expandvars(os.environ.get("SSLKEYLOGFILE"))
    else:
        sslkeylogfile = None
    if sslkeylogfile:
        context.keylog_filename = sslkeylogfile

    return context


def _ssl_material_revision(path: str | None) -> typing.Any:
    """Record file or directory identity and metadata for rotation detection."""
    if path is None:
        return None
    try:
        item = os.stat(path)
    except OSError as error:
        return ("unavailable", error.errno)
    revision = (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if not stat.S_ISDIR(item.st_mode):
        return revision
    # Existing capath entries can be edited in place, or symlink targets
    # replaced, without modifying the parent directory's mtime. Observe each
    # entry rather than accidentally pinning an old trust store forever.
    try:
        with os.scandir(path) as entries:
            children = []
            for entry in entries:
                try:
                    child = entry.stat()  # Follow capath's hashed symlinks.
                    child_revision: tuple[typing.Any, ...] = (
                        child.st_dev,
                        child.st_ino,
                        child.st_size,
                        child.st_mtime_ns,
                    )
                except OSError as error:
                    child_revision = ("unavailable", error.errno)
                children.append((entry.name, child_revision))
    except OSError as error:
        return (revision, "unavailable", error.errno)
    return (revision, tuple(sorted(children)))


class _CAPathWatcher:
    """Amortize CApath revisions without indefinitely caching trust material.

    Linux inotify watches the directory and any directories containing targets
    of symlinked certificates. Missed notifications and unsupported platforms
    fall back to metadata scanning; this never reloads a live SSLContext.
    """

    __slots__ = (
        "path",
        "revision",
        "last_scan",
        "generation",
        "pid",
        "fd",
        "__weakref__",
    )
    # Bound missed-event staleness to 100 ms without a scan per connection.
    _RESCAN_SECONDS = 0.1
    _MUTATIONS = (
        0x00000002  # IN_MODIFY
        | 0x00000004  # IN_ATTRIB
        | 0x00000008  # IN_CLOSE_WRITE
        | 0x00000100  # IN_CREATE
        | 0x00000200  # IN_DELETE
        | 0x00000400  # IN_DELETE_SELF
        | 0x00000800  # IN_MOVE_SELF
        | 0x00000040  # IN_MOVED_FROM
        | 0x00000080  # IN_MOVED_TO
    )
    _INVALIDATED = 0x00008000 | 0x00004000 | 0x00000400 | 0x00000800
    _WATCH_LAYOUT_CHANGED = (
        _INVALIDATED | 0x00000100 | 0x00000200 | 0x00000040 | 0x00000080
    )

    def __init__(self, path: str) -> None:
        self.path = path
        self.revision = _ssl_material_revision(path)
        self.last_scan = time.monotonic()
        self.generation = 0
        self.pid = os.getpid()
        self.fd: int | None = None
        if sys.platform != "linux" or not os.path.isdir(path):
            return
        fd = -1
        try:
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            init = libc.inotify_init1
            init.argtypes = [ctypes.c_int]
            init.restype = ctypes.c_int
            fd = init(os.O_NONBLOCK | os.O_CLOEXEC)
            if fd < 0:
                return
            add_watch = libc.inotify_add_watch
            add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            add_watch.restype = ctypes.c_int
            directories = {path}
            with os.scandir(path) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        directories.add(os.path.dirname(os.path.realpath(entry.path)))
            for directory in directories:
                if add_watch(fd, os.fsencode(directory), self._MUTATIONS) < 0:
                    raise OSError(
                        ctypes.get_errno(), "CApath watch could not be installed"
                    )
            self.fd = fd
            # Watch before the authoritative snapshot: mutations between
            # installation and trust load are observable by the next read.
            self.revision = _ssl_material_revision(path)
            self.last_scan = time.monotonic()
        except (OSError, AttributeError, ImportError):
            if fd >= 0:
                os.close(fd)

    def _disable(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def current_revision(self) -> typing.Any:
        changed = False
        invalidated = False
        if os.getpid() != self.pid:
            # Forked processes share the same inotify queue. Reading it in
            # the child could consume the parent's rotation notification.
            self._disable()
            self.pid = os.getpid()
            invalidated = True
        if self.fd is not None:
            try:
                while True:
                    try:
                        events = os.read(self.fd, 65536)
                    except BlockingIOError:
                        break
                    if not events:
                        self._disable()
                        break
                    changed = True
                    offset = 0
                    while offset + 16 <= len(events):
                        _, mask, _, name_length = struct.unpack_from(
                            "iIII", events, offset
                        )
                        if mask & self._WATCH_LAYOUT_CHANGED:
                            invalidated = True
                        offset += 16 + name_length
            except OSError:
                invalidated = True
        if invalidated:
            # New symlink targets need new watches. Keep this monitor alive
            # for earlier contexts (which must fail closed) but do not give
            # it to newly created contexts after directory layout changes.
            self._disable()
            if _CAPATH_WATCHERS.get(self.path) is self:
                del _CAPATH_WATCHERS[self.path]
        if changed:
            # Even a metadata-preserving rewrite must invalidate existing
            # contexts. Track events independently of size/mtime snapshots.
            self.generation += 1
        now = time.monotonic()
        if self.fd is None or changed or now - self.last_scan >= self._RESCAN_SECONDS:
            self.revision = _ssl_material_revision(self.path)
            self.last_scan = now
        return self.generation, self.revision

    def __del__(self) -> None:
        if self.fd is not None:
            self._disable()


def _ca_path_watcher(path: str) -> _CAPathWatcher:
    path = os.path.abspath(path)
    watcher = _CAPATH_WATCHERS.get(path)
    if watcher is None:
        watcher = _CAPathWatcher(path)
        _CAPATH_WATCHERS[path] = watcher
    return watcher


def _configure_shared_ssl_context(
    context: ssl.SSLContext,
    *,
    verify_mode: VerifyMode | None,
    disable_hostname_check: bool,
    ca_certs: str | None,
    ca_cert_dir: str | None,
    ca_cert_data: None | str | bytes,
    certfile: str | None,
    keyfile: str | None,
    key_password: str | None,
) -> None:
    """Prepare a supplied context exactly once, before any urllib3 TLS objects.

    Certificate fingerprints are checked on every reuse. A changed trust
    bundle or conflicting settings cannot be reloaded into an in-use context;
    require a fresh context instead of silently keeping stale CA material.
    """
    with _SHARED_CONTEXT_LOCK:
        requested_verify_mode: int = (
            context.verify_mode if verify_mode is None else verify_mode
        )
        requested_check_hostname = (
            False
            if disable_hostname_check
            else getattr(context, "check_hostname", False)
        )
        parameters = (
            requested_verify_mode,
            requested_check_hostname,
            # Once we disable built-in hostname verification for manual
            # checking, a later caller must not silently inherit that policy.
            disable_hostname_check,
            ca_certs,
            ca_cert_dir,
            ca_cert_data,
            certfile,
            keyfile,
            key_password,
            tuple(ALPN_PROTOCOLS),
        )
        prior = _SHARED_CONTEXT_CONFIGS.get(context)
        watcher = (
            prior[2]
            if prior is not None
            else _ca_path_watcher(ca_cert_dir) if ca_cert_dir is not None else None
        )
        versions = (
            _ssl_material_revision(ca_certs),
            (
                watcher.current_revision()
                if watcher
                else _ssl_material_revision(ca_cert_dir)
            ),
            _ssl_material_revision(certfile),
            _ssl_material_revision(keyfile),
        )
        desired = (parameters, versions)
        if prior is not None:
            if (
                prior[:2] != desired
                or context.verify_mode != requested_verify_mode
                or getattr(context, "check_hostname", False) != requested_check_hostname
            ):
                raise SSLError(
                    "TLS settings or certificate material changed on an in-use "
                    "SSLContext; create a new SSLContext and connection pool."
                )
            return

        # check_hostname must be disabled before CERT_NONE can be selected.
        if disable_hostname_check and getattr(context, "check_hostname", False):
            context.check_hostname = False
        if verify_mode is not None and context.verify_mode != verify_mode:
            context.verify_mode = verify_mode

        if ca_certs or ca_cert_dir or ca_cert_data:
            try:
                context.load_verify_locations(ca_certs, ca_cert_dir, ca_cert_data)
            except OSError as error:
                raise SSLError(error) from error

        if keyfile and key_password is None and _is_key_file_encrypted(keyfile):
            raise SSLError("Client private key is encrypted, password is required")
        if certfile:
            if key_password is None:
                context.load_cert_chain(certfile, keyfile)
            else:
                context.load_cert_chain(certfile, keyfile, key_password)

        context.set_alpn_protocols(ALPN_PROTOCOLS)
        if versions != (
            _ssl_material_revision(ca_certs),
            (
                watcher.current_revision()
                if watcher
                else _ssl_material_revision(ca_cert_dir)
            ),
            _ssl_material_revision(certfile),
            _ssl_material_revision(keyfile),
        ):
            raise SSLError(
                "Certificate material changed during TLS setup; create a new SSLContext."
            )
        _SHARED_CONTEXT_CONFIGS[context] = (parameters, versions, watcher)


@typing.overload
def ssl_wrap_socket(
    sock: socket.socket,
    keyfile: str | None = ...,
    certfile: str | None = ...,
    cert_reqs: int | None = ...,
    ca_certs: str | None = ...,
    server_hostname: str | None = ...,
    ssl_version: int | None = ...,
    ciphers: str | None = ...,
    ssl_context: ssl.SSLContext | None = ...,
    ca_cert_dir: str | None = ...,
    key_password: str | None = ...,
    ca_cert_data: None | str | bytes = ...,
    tls_in_tls: typing.Literal[False] = ...,
    _context_verify_mode: VerifyMode | None = ...,
    _context_disable_hostname_check: bool = ...,
    _context_is_fresh: bool = ...,
) -> ssl.SSLSocket: ...


@typing.overload
def ssl_wrap_socket(
    sock: socket.socket,
    keyfile: str | None = ...,
    certfile: str | None = ...,
    cert_reqs: int | None = ...,
    ca_certs: str | None = ...,
    server_hostname: str | None = ...,
    ssl_version: int | None = ...,
    ciphers: str | None = ...,
    ssl_context: ssl.SSLContext | None = ...,
    ca_cert_dir: str | None = ...,
    key_password: str | None = ...,
    ca_cert_data: None | str | bytes = ...,
    tls_in_tls: bool = ...,
    _context_verify_mode: VerifyMode | None = ...,
    _context_disable_hostname_check: bool = ...,
    _context_is_fresh: bool = ...,
) -> ssl.SSLSocket | SSLTransportType: ...


def ssl_wrap_socket(
    sock: socket.socket,
    keyfile: str | None = None,
    certfile: str | None = None,
    cert_reqs: int | None = None,
    ca_certs: str | None = None,
    server_hostname: str | None = None,
    ssl_version: int | None = None,
    ciphers: str | None = None,
    ssl_context: ssl.SSLContext | None = None,
    ca_cert_dir: str | None = None,
    key_password: str | None = None,
    ca_cert_data: None | str | bytes = None,
    tls_in_tls: bool = False,
    _context_verify_mode: VerifyMode | None = None,
    _context_disable_hostname_check: bool = False,
    _context_is_fresh: bool = False,
) -> ssl.SSLSocket | SSLTransportType:
    """
    All arguments except for server_hostname, ssl_context, tls_in_tls, ca_cert_data and
    ca_cert_dir have the same meaning as they do when using
    :func:`ssl.create_default_context`, :meth:`ssl.SSLContext.load_cert_chain`,
    :meth:`ssl.SSLContext.set_ciphers` and :meth:`ssl.SSLContext.wrap_socket`.

    :param server_hostname:
        When SNI is supported, the expected hostname of the certificate
    :param ssl_context:
        A pre-made :class:`SSLContext` object. If none is provided, one will
        be created using :func:`create_urllib3_context`.
    :param ciphers:
        A string of ciphers we wish the client to support.
    :param ca_cert_dir:
        A directory containing CA certificates in multiple separate files, as
        supported by OpenSSL's -CApath flag or the capath argument to
        SSLContext.load_verify_locations().
    :param key_password:
        Optional password if the keyfile is encrypted.
    :param ca_cert_data:
        Optional string containing CA certificates in PEM format suitable for
        passing as the cadata parameter to SSLContext.load_verify_locations()
    :param tls_in_tls:
        Use SSLTransport to wrap the existing socket.
    """
    context = ssl_context
    if context is None or _context_is_fresh:
        # A fresh context belongs to this socket; don't serialize unrelated
        # connections behind the global lock for caller-shared contexts.
        if context is None:
            context = create_urllib3_context(ssl_version, cert_reqs, ciphers=ciphers)
        if ca_certs or ca_cert_dir or ca_cert_data:
            try:
                context.load_verify_locations(ca_certs, ca_cert_dir, ca_cert_data)
            except OSError as e:
                raise SSLError(e) from e
        elif not _context_is_fresh and hasattr(context, "load_default_certs"):
            # The high-level connection caller has already loaded the OS CA
            # store into its freshly created context before passing it here.
            context.load_default_certs()
        if keyfile and key_password is None and _is_key_file_encrypted(keyfile):
            raise SSLError("Client private key is encrypted, password is required")
        if certfile:
            if key_password is None:
                context.load_cert_chain(certfile, keyfile)
            else:
                context.load_cert_chain(certfile, keyfile, key_password)
        context.set_alpn_protocols(ALPN_PROTOCOLS)
    else:
        _configure_shared_ssl_context(
            context,
            verify_mode=_context_verify_mode,
            disable_hostname_check=_context_disable_hostname_check,
            ca_certs=ca_certs,
            ca_cert_dir=ca_cert_dir,
            ca_cert_data=ca_cert_data,
            certfile=certfile,
            keyfile=keyfile,
            key_password=key_password,
        )

    ssl_sock = _ssl_wrap_socket_impl(sock, context, tls_in_tls, server_hostname)
    return ssl_sock


def is_ipaddress(hostname: str | bytes) -> bool:
    """Detects whether the hostname given is an IPv4 or IPv6 address.
    Also detects IPv6 addresses with Zone IDs.

    :param str hostname: Hostname to examine.
    :return: True if the hostname is an IP address, False otherwise.
    """
    if isinstance(hostname, bytes):
        # IDN A-label bytes are ASCII compatible.
        hostname = hostname.decode("ascii")
    return bool(_IPV4_RE.match(hostname) or _BRACELESS_IPV6_ADDRZ_RE.match(hostname))


def _is_key_file_encrypted(key_file: str) -> bool:
    """Detects if a key file is encrypted or not."""
    with open(key_file) as f:
        for line in f:
            # Look for Proc-Type: 4,ENCRYPTED
            if "ENCRYPTED" in line:
                return True

    return False


def _ssl_wrap_socket_impl(
    sock: socket.socket,
    ssl_context: ssl.SSLContext,
    tls_in_tls: bool,
    server_hostname: str | None = None,
) -> ssl.SSLSocket | SSLTransportType:
    if tls_in_tls:
        if not SSLTransport:
            # Import error, ssl is not available.
            raise ProxySchemeUnsupported(
                "TLS in TLS requires support for the 'ssl' module"
            )

        SSLTransport._validate_ssl_context_for_tls_in_tls(ssl_context)
        return SSLTransport(sock, ssl_context, server_hostname)

    return ssl_context.wrap_socket(sock, server_hostname=server_hostname)
