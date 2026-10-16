"""Transporte streamable HTTP local, para um processo atender várias sessões do cliente MCP.

Escuta só em 127.0.0.1 e exige `Authorization: Bearer <token>` em toda requisição.
O token vem de um arquivo que só o usuário lê (`--token-file`). A proteção contra
DNS rebinding (Host/Origin locais) é a do próprio FastMCP para host local.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
from pathlib import Path

from mcp.server.fastmcp import FastMCP

_MIN_TOKEN_LEN = 32


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Servidor MCP (stdio por padrão).")
    parser.add_argument("--http", action="store_true", help="servir streamable HTTP em 127.0.0.1")
    parser.add_argument("--port", type=int, help="porta local do modo --http")
    parser.add_argument("--token-file", type=Path, help="arquivo com o token Bearer do modo --http")
    args = parser.parse_args(argv)
    if args.http and (args.port is None or args.token_file is None):
        parser.error("--http exige --port e --token-file")
    return args


def _read_token(path: Path) -> str:
    token = path.read_text(encoding="utf-8").strip()
    if len(token) < _MIN_TOKEN_LEN:
        raise SystemExit(f"token em {path} curto demais (mínimo {_MIN_TOKEN_LEN} caracteres)")
    return token


class _BearerAuth:
    """Middleware ASGI que recusa com 401 a requisição HTTP sem o token esperado."""

    def __init__(self, app, token: str) -> None:
        self._app = app
        self._expected = hashlib.sha256(f"Bearer {token}".encode()).digest()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            got = dict(scope["headers"]).get(b"authorization", b"")
            if not hmac.compare_digest(hashlib.sha256(got).digest(), self._expected):
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", b"Bearer")],
                })
                await send({"type": "http.response.body", "body": b"nao autorizado"})
                return
        await self._app(scope, receive, send)


def serve(mcp: FastMCP, port: int, token_file: Path) -> None:
    import uvicorn

    app = _BearerAuth(mcp.streamable_http_app(), _read_token(token_file))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
