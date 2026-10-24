"""HTTP to a peer (portal or neighbour) with a hard size limit and the number of bytes that went over the link.

The size a peer declares (e.g. in /pki/summary) is untrusted: the download is aborted as soon as the body
exceeds it, so a lying or broken peer cannot fill a slow radio link or the disk.

wire_bytes counts what an HTTP/1.1 exchange puts on the link: request line + headers + body and status line +
headers + body (without TCP/IP overhead). It is an estimate built from the headers actually sent and received.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from urllib.parse import urlparse

import requests

import config


class WireError(Exception):
    """The exchange failed: peer unreachable, HTTP error, body larger than allowed, bad JSON."""


@dataclass
class Fetched:
    status: int
    body: bytes
    wire_bytes: int

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except ValueError as exc:
            raise WireError(f"Niepoprawny JSON od sąsiada: {exc}") from exc


def _headers_size(items) -> int:
    return sum(len(str(k)) + len(str(v)) + 4 for k, v in items) + 2  # "k: v\r\n" ... "\r\n"


def client_wire_bytes(resp: requests.Response, body_len: int) -> int:
    req = resp.request
    url = urlparse(req.url)
    request = (len(f"{req.method} {req.path_url} HTTP/1.1\r\n") + len(f"Host: {url.netloc}\r\n")
               + _headers_size(req.headers.items()) + len(req.body or b""))
    response = len(f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n") + _headers_size(resp.headers.items()) + body_len
    return request + response


def server_wire_bytes(method: str, path: str, request_headers: Mapping, request_body_len: int,
                      status: int, response_headers, body_len: int) -> int:
    """The same estimate on the serving side (FastAPI request + Starlette raw response headers)."""
    request = len(f"{method} {path} HTTP/1.1\r\n") + _headers_size(request_headers.items()) + request_body_len
    response = (len(f"HTTP/1.1 {status} OK\r\n")
                + _headers_size((k.decode(), v.decode()) for k, v in response_headers) + body_len)
    return request + response


def _timeout():
    return (config.P2P_CONNECT_TIMEOUT, config.P2P_READ_TIMEOUT)


def _read_limited(resp: requests.Response, limit: int) -> bytes:
    chunks, total = [], 0
    for chunk in resp.iter_content(chunk_size=4096):
        total += len(chunk)
        if total > limit:
            resp.close()
            raise WireError(f"Odpowiedź przekracza limit {limit} B – pobieranie przerwane.")
        chunks.append(chunk)
    return b"".join(chunks)


def _send(method: str, url: str, limit: int, extra_headers: Optional[dict] = None, **kwargs) -> Fetched:
    headers = {"User-Agent": f"EdgeClient/{config.NODE_ID}", **(extra_headers or {})}
    try:
        resp = requests.request(method, url, headers=headers, stream=True, timeout=_timeout(), **kwargs)
    except requests.RequestException as exc:
        raise WireError(f"{url}: {type(exc).__name__} ({exc})") from exc
    with resp:
        if resp.status_code != 200:
            body = resp.raw.read(512, decode_content=True) or b""
            raise WireError(f"{url}: HTTP {resp.status_code} {body[:200]!r}")
        try:
            body = _read_limited(resp, limit)
        except requests.RequestException as exc:  # link lost in the middle of the body
            raise WireError(f"{url}: transfer przerwany ({type(exc).__name__})") from exc
        return Fetched(resp.status_code, body, client_wire_bytes(resp, len(body)))


def get(url: str, limit: int) -> Fetched:
    """GET with the body limited to `limit` bytes (pass min(declared size, hard maximum))."""
    return _send("GET", url, limit)


def post_json(url: str, payload: Any, limit: int) -> Fetched:
    body = json.dumps(payload, separators=(",", ":")).encode()
    return _send("POST", url, limit, {"Content-Type": "application/json"}, data=body)


def post_bytes(url: str, body: bytes, content_type: str, limit: int) -> Fetched:
    return _send("POST", url, limit, {"Content-Type": content_type}, data=body)


def peer_url(peer: Mapping[str, Any], path: str) -> str:
    return f"{peer['url'].rstrip('/')}{path}"


def json_payload_size(obj: Any) -> int:
    return len(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode())


def optional_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
