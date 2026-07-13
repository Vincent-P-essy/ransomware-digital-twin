"""Bounded local API and dependency-free dashboard."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Type
from urllib.parse import unquote, urlparse

from . import __version__
from .bundle import default_bundle_root, load_bundle
from .errors import DigitalTwinError, ValidationError
from .jsonutil import loads_json
from .models import to_jsonable
from .simulator import run_comparison, run_simulation


MAX_REQUEST_BYTES = 16_384
_WEB_DIR = Path(__file__).with_name("web")


def handler_for(bundle_root: Path) -> Type[BaseHTTPRequestHandler]:
    configured_root = bundle_root.resolve()

    class Handler(BaseHTTPRequestHandler):
        server_version = "ResilienceTwin/0.1"

        def log_message(self, format: str, *args: object) -> None:
            return

        def _headers(
            self, status: int, content_type: str, length: int, cache: str = "no-store"
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            )
            self.end_headers()

        def _json(self, status: int, value: Any) -> None:
            body = (
                json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n"
            ).encode()
            self._headers(status, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def _asset(self, path: Path, content_type: str) -> None:
            try:
                body = path.read_bytes()
            except FileNotFoundError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "asset_not_found"})
                return
            self._headers(HTTPStatus.OK, content_type, len(body), "public, max-age=300")
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = unquote(urlparse(self.path).path)
            try:
                if path == "/":
                    self._asset(_WEB_DIR / "index.html", "text/html; charset=utf-8")
                elif path == "/assets/app.js":
                    self._asset(_WEB_DIR / "app.js", "text/javascript; charset=utf-8")
                elif path == "/assets/styles.css":
                    self._asset(_WEB_DIR / "styles.css", "text/css; charset=utf-8")
                elif path == "/api/v1/health":
                    self._json(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "version": __version__,
                            "execution_mode": "simulation-only",
                            "external_effects": "none",
                        },
                    )
                elif path in {"/api/v1/topology", "/api/v1/profiles"}:
                    bundle = load_bundle(configured_root)
                    if path.endswith("topology"):
                        self._json(
                            HTTPStatus.OK, {"topology": to_jsonable(bundle.topology)}
                        )
                    else:
                        self._json(
                            HTTPStatus.OK,
                            {
                                "profiles": [
                                    to_jsonable(item) for item in bundle.profiles
                                ]
                            },
                        )
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            except DigitalTwinError as exc:
                self._json(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    {"error": type(exc).__name__, "detail": str(exc)},
                )

        def _request_object(self) -> Any:
            if self.headers.get_content_type() != "application/json":
                raise _RequestFailure(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "application_json_required"
                )
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise _RequestFailure(
                    HTTPStatus.BAD_REQUEST, "invalid_content_length"
                ) from exc
            if not 0 < length <= MAX_REQUEST_BYTES:
                raise _RequestFailure(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request_size_rejected"
                )
            try:
                return loads_json(
                    self.rfile.read(length).decode("utf-8"), "API request body"
                )
            except UnicodeDecodeError as exc:
                raise _RequestFailure(HTTPStatus.BAD_REQUEST, "invalid_json") from exc
            except ValidationError as exc:
                raise _RequestFailure(
                    HTTPStatus.BAD_REQUEST, "invalid_json", str(exc)
                ) from exc

        def do_POST(self) -> None:  # noqa: N802
            path = unquote(urlparse(self.path).path)
            if path not in {"/api/v1/simulate", "/api/v1/compare"}:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            try:
                raw = self._request_object()
                if not isinstance(raw, dict):
                    raise _RequestFailure(HTTPStatus.BAD_REQUEST, "object_required")
                bundle = load_bundle(configured_root)
                if path.endswith("simulate"):
                    if set(raw) != {"profile_id"} or not isinstance(
                        raw["profile_id"], str
                    ):
                        raise _RequestFailure(
                            HTTPStatus.BAD_REQUEST, "profile_id_required"
                        )
                    result = run_simulation(bundle, raw["profile_id"])
                else:
                    if set(raw) != {"profile_ids"} or not isinstance(
                        raw["profile_ids"], list
                    ):
                        raise _RequestFailure(
                            HTTPStatus.BAD_REQUEST, "profile_ids_required"
                        )
                    if not all(isinstance(item, str) for item in raw["profile_ids"]):
                        raise _RequestFailure(
                            HTTPStatus.BAD_REQUEST, "profile_ids_invalid"
                        )
                    result = run_comparison(bundle, raw["profile_ids"])
                self._json(HTTPStatus.OK, result)
            except _RequestFailure as exc:
                body = {"error": exc.code}
                if exc.detail:
                    body["detail"] = exc.detail
                self._json(exc.status, body)
            except DigitalTwinError as exc:
                self._json(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    {"error": type(exc).__name__, "detail": str(exc)},
                )

    return Handler


class _RequestFailure(Exception):
    def __init__(self, status: int, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.detail = detail


def create_server(
    host: str, port: int, bundle_root: Path | None = None
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(
        (host, port), handler_for(bundle_root or default_bundle_root())
    )
    server.daemon_threads = True
    return server


def serve(host: str, port: int, bundle_root: Path | None = None) -> None:
    server = create_server(host, port, bundle_root)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
