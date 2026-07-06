"""Cliente HTTP do Portal do Cliente TOTVS (suporte.totvs.com).

Responsavel por:
  1. Autenticacao automatica (Fluig Identity: login + MFA/TOTP -> SAML SSO ->
     ACS -> jwt/create) resultando no `token` (JWT Zendesk, ~13h) usado pela
     API de tickets em `ti-services.totvs.com.br`.
  2. Cache cifrado (Fernet) desse token em disco pra nao refazer a danca SAML
     a cada chamada / restart do MCP.
  3. Chamadas read-only na API de tickets (`post_ticket`), injetando `token` e
     `customerCode` no body como o portal faz.

Segredos (username, senha, seed TOTP) ficam no keyring nativo do OS; a senha
NUNCA fica em `self` entre logins (lida sob demanda). Ver SECURITY / CLAUDE.md.

O miolo do login foi mapeado de um HAR do portal, mas alguns nomes de campo de
resposta (ex: como o `mfa_token` volta no 403 do login) sao confirmados ao vivo
via `python -m totvs_tickets_mcp.probe_login`. Pontos incertos estao marcados
com `# CONFIRMAR` e resolvidos de forma tolerante (busca flexivel de chave).
"""

from __future__ import annotations

import base64
import datetime as dt
import html
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

# --- Endpoints (mapeados do HAR do portal) --------------------------------
FLUIG_BASE = "https://totvs.fluigidentity.com"
PORTAL_BASE = "https://suporte.totvs.com"
TI_BASE = "https://ti-services.totvs.com.br"
TI_PREFIX = "/customer-portal-backend"

# Pagina protegida do portal que dispara o SP-initiated SSO (retorna o form
# auto-post com o SAMLRequest quando nao ha sessao).
PORTAL_PROTECTED_URL = (
    PORTAL_BASE + "/portal/p/10098/customer-portal-dashboard/tickets"
)
# Endpoint que emite o token de tickets (JWT Zendesk) a partir da sessao do portal.
JWT_CREATE_PATH = "/customer-portal-wdgt-contact-customize/api/rest/portal/jwt/create"

# Login Fluig
FLUIG_LOGIN_PATH = "/api/auth/v1/login"
FLUIG_TOKEN_PATH = "/api/auth/v1/token"
FLUIG_MFA_TOTP_GRANT = "http://fluigidentity.com/api/mfa/totp"
FLUIG_DOMAIN = "totvs"

# --- Keyring / cache ------------------------------------------------------
KEYRING_SERVICE = "totvs-tickets-mcp"
KEYRING_USERNAME_KEY = "__username__"
KEYRING_SEED_KEY = "__totp_seed__"
KEYRING_TOKEN_KEY_KEY = "__token_key__"  # chave Fernet pra cifrar o cache do token
TOKEN_FILE = Path.home() / ".totvs-tickets-mcp-token.json"
AUDIT_LOG_FILE = Path.home() / ".totvs-tickets-mcp-audit.log"


def _dbg(msg: str) -> None:
    """Log de debug pra STDERR (stdout e o canal do protocolo MCP — nao usar)."""
    if os.environ.get("TOTVS_DEBUG"):
        print(f"[totvs-tickets] {msg}", file=sys.stderr, flush=True)


def _describe(obj: Any, _depth: int = 0) -> Any:
    """Descreve a forma de um JSON sem expor valores sensiveis.

    Strings viram `<str:len>`; usado no debug do login pra revelar nomes de
    campo (mfa_token, access_token, ...) sem vazar os valores.
    """
    if isinstance(obj, dict):
        return {k: _describe(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_describe(obj[0], _depth + 1), f"...<{len(obj)} itens>"] if obj else []
    if isinstance(obj, str):
        return f"<str:{len(obj)}>"
    return obj


def _audit(method: str, path: str, status: int) -> None:
    """Log de auditoria opcional (TOTVS_AUDIT_LOG=1): timestamp + verbo + path + status.

    Nunca registra body, headers nem credenciais.
    """
    if not os.environ.get("TOTVS_AUDIT_LOG"):
        return
    try:
        ts = dt.datetime.now().isoformat(timespec="seconds")
        with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{ts} {method} {path} {status}\n")
    except Exception:
        pass


# Cookies/anti-bot da TOTVS (CloudFront/WAF) rejeitam cliente sem cara de browser.
# Esses headers replicam o Chrome capturado no HAR e vao em todas as chamadas.
_BROWSER_HEADERS = {
    "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
    ),
    "sec-ch-ua": '"Chromium";v="143", "Not A(Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

# Headers das chamadas na API de tickets (ti-services). Auth NAO usa header —
# vai o `token` no body. So precisa parecer o front do portal (origin/referer).
_TI_HEADERS = {
    **_BROWSER_HEADERS,
    "accept": "application/json, text/plain, */*",
    "content-type": "application/json",
    "origin": PORTAL_BASE,
    "referer": PORTAL_BASE + "/",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
}


# --- Fernet (cifra do cache de token em disco) ----------------------------
def _get_or_create_fernet_key() -> bytes | None:
    try:
        import keyring
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    try:
        existing = keyring.get_password(KEYRING_SERVICE, KEYRING_TOKEN_KEY_KEY)
        if existing:
            return existing.encode("ascii")
        new_key = Fernet.generate_key()
        keyring.set_password(KEYRING_SERVICE, KEYRING_TOKEN_KEY_KEY, new_key.decode("ascii"))
        return new_key
    except Exception:
        return None


def _fernet_encrypt(plaintext: bytes) -> bytes | None:
    key = _get_or_create_fernet_key()
    if key is None:
        return None
    try:
        from cryptography.fernet import Fernet

        return Fernet(key).encrypt(plaintext)
    except Exception:
        return None


def _fernet_decrypt(ciphertext: bytes) -> bytes | None:
    key = _get_or_create_fernet_key()
    if key is None:
        return None
    try:
        from cryptography.fernet import Fernet, InvalidToken

        try:
            return Fernet(key).decrypt(ciphertext)
        except InvalidToken:
            return None
    except Exception:
        return None


# --- Credenciais ----------------------------------------------------------
def _read_username() -> str | None:
    u = os.environ.get("TOTVS_USERNAME")
    if u:
        return u
    try:
        import keyring

        return keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME_KEY)
    except Exception:
        return None


def _read_password() -> str | None:
    p = os.environ.get("TOTVS_PASSWORD")
    if p:
        return p
    try:
        import keyring

        user = _read_username()
        if user:
            return keyring.get_password(KEYRING_SERVICE, user)
    except Exception:
        return None
    return None


def _read_totp_seed() -> str | None:
    s = os.environ.get("TOTVS_TOTP_SEED")
    if s:
        return s
    try:
        import keyring

        return keyring.get_password(KEYRING_SERVICE, KEYRING_SEED_KEY)
    except Exception:
        return None


def _totp_now(seed: str) -> str:
    """Gera o codigo TOTP de 6 digitos a partir do seed do autenticador."""
    import pyotp

    # Aceita seed com espacos/lowercase (como o app mostra) — pyotp exige base32
    # sem espacos e maiusculo.
    cleaned = seed.replace(" ", "").upper()
    return pyotp.TOTP(cleaned).now()


# --- Parser de form SAML (auto-post) --------------------------------------
def _parse_auto_post_form(html_text: str) -> tuple[str | None, dict[str, str]]:
    """Extrai (action, {inputs}) do primeiro <form> auto-submit de uma pagina SAML.

    Serve tanto pro passo SP->IdP (SAMLRequest) quanto IdP->SP/ACS (SAMLResponse).
    """
    import re

    if not html_text:
        return None, {}
    fm = re.search(r"<form\b[^>]*>", html_text, re.I)
    if not fm:
        return None, {}
    form_tag = fm.group(0)
    am = re.search(r"""action\s*=\s*["']([^"']+)["']""", form_tag, re.I)
    action = html.unescape(am.group(1)) if am else None
    # Limita a busca de inputs ao corpo do form.
    end = html_text.lower().find("</form>", fm.end())
    body = html_text[fm.end(): end if end != -1 else len(html_text)]
    inputs: dict[str, str] = {}
    for tag in re.finditer(r"<input\b[^>]*>", body, re.I):
        t = tag.group(0)
        nm = re.search(r"""name\s*=\s*["']([^"']+)["']""", t, re.I)
        if not nm:
            continue
        vm = re.search(r"""value\s*=\s*["']([^"']*)["']""", t, re.I)
        inputs[nm.group(1)] = html.unescape(vm.group(1)) if vm else ""
    return action, inputs


def _find_key(obj: Any, *needles: str) -> Any:
    """Busca recursiva do primeiro valor cuja chave contem um dos `needles`.

    Tolerante a variacoes de nome (mfa_token / mfaToken / token). Retorna o
    valor (str) ou None.
    """
    needles_l = [n.lower() for n in needles]
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                kl = str(k).lower()
                if isinstance(v, str) and any(n in kl for n in needles_l):
                    return v
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}


class LoginError(RuntimeError):
    """Erro no fluxo de login. Mensagem sanitizada (sem senha/token)."""


class TotvsTicketsClient:
    def __init__(self) -> None:
        self.username = _read_username()
        if not self.username:
            raise RuntimeError(
                "Credenciais nao encontradas. Rode: totvs-tickets-setup"
            )
        self._token: str | None = None       # JWT de tickets (ti-services)
        self._exp: int = 0
        self._claims: dict[str, Any] = {}
        # httpx.Client com cookie jar persistente (essencial pra danca SAML).
        self._http = httpx.Client(
            timeout=float(os.environ.get("TOTVS_TIMEOUT", "60")),
            headers=_BROWSER_HEADERS,
            follow_redirects=True,
        )
        self._load_cached()

    # ------------------------------------------------------------------ cache
    def _cache_disabled(self) -> bool:
        return bool(os.environ.get("TOTVS_NO_TOKEN_CACHE"))

    def _load_cached(self) -> None:
        if self._cache_disabled() or not TOKEN_FILE.exists():
            return
        try:
            plaintext = _fernet_decrypt(TOKEN_FILE.read_bytes())
            if plaintext is None:
                try:
                    TOKEN_FILE.unlink()
                except Exception:
                    pass
                return
            data = json.loads(plaintext.decode("utf-8"))
            if data.get("exp", 0) > time.time() + 60:
                self._token = data["token"]
                self._exp = int(data["exp"])
                self._claims = _decode_jwt_payload(self._token)
                _dbg(f"token de cache valido (exp em {self._exp - int(time.time())}s)")
        except Exception:
            pass

    def _save_cached(self) -> None:
        if self._cache_disabled() or not self._token:
            return
        try:
            plaintext = json.dumps({"token": self._token, "exp": self._exp}).encode("utf-8")
            ct = _fernet_encrypt(plaintext)
            if ct is None:
                return
            TOKEN_FILE.write_bytes(ct)
            try:
                os.chmod(TOKEN_FILE, 0o600)
            except Exception:
                pass
        except Exception:
            pass

    # ------------------------------------------------------------------ token/IDs
    @property
    def claims(self) -> dict[str, Any]:
        return self._claims

    @property
    def user_id(self) -> Any:
        return (self._claims.get("zendesk") or {}).get("id")

    @property
    def organizations(self) -> list[dict[str, Any]]:
        out = []
        for o in self._claims.get("organizations", []) or []:
            out.append(
                {"id": o.get("id"), "external_id": o.get("external_id"), "name": o.get("name")}
            )
        return out

    @property
    def primary_org_id(self) -> str:
        oid = (self._claims.get("zendesk") or {}).get("organization_id")
        return str(oid) if oid is not None else ""

    @property
    def default_customer_code(self) -> str:
        """customerCode padrao = external_id da organizacao primaria do usuario."""
        pid = self.primary_org_id
        for o in self._claims.get("organizations", []) or []:
            if str(o.get("id")) == pid:
                return o.get("external_id") or ""
        orgs = self._claims.get("organizations") or []
        return (orgs[0].get("external_id") if orgs else "") or ""

    def _ensure_token(self) -> None:
        if not self._token or self._exp < time.time() + 60:
            self.login()

    # ------------------------------------------------------------------ login
    def login(self) -> None:
        """Executa a cadeia completa de auth e popula self._token (JWT de tickets)."""
        password = _read_password()
        seed = _read_totp_seed()
        if not password:
            raise RuntimeError("Senha nao encontrada. Rode: totvs-tickets-setup")
        if not seed:
            raise RuntimeError("Seed TOTP nao encontrado. Rode: totvs-tickets-setup")
        try:
            token = self._run_saml_login(self.username, password, seed)
        finally:
            del password
            del seed
        self._token = token
        self._claims = _decode_jwt_payload(token)
        self._exp = int(self._claims.get("exp", time.time() + 12 * 3600))
        _dbg(
            f"login OK. customerCode={self.default_customer_code} "
            f"userId={self.user_id} orgs={[o['external_id'] for o in self.organizations]}"
        )
        self._save_cached()

    def _run_saml_login(self, username: str, password: str, seed: str) -> str:
        c = self._http

        # -- Passo 0: pagina protegida do portal -> form auto-post com SAMLRequest
        _dbg("passo 0: GET pagina protegida do portal (dispara SP-init SSO)")
        r0 = c.get(PORTAL_PROTECTED_URL)
        action1, inputs1 = _parse_auto_post_form(r0.text)
        if not action1 or "SAMLRequest" not in inputs1:
            raise LoginError(
                "passo 0 falhou: nao achei o form SAMLRequest na pagina do portal "
                f"(status {r0.status_code}, len {len(r0.text)}). "
                "Possivel challenge de WAF/anti-bot ou sessao ja ativa."
            )
        _dbg(f"passo 0 OK: SP->IdP action={action1} inputs={list(inputs1)}")

        # -- Passo 1: POST SAMLRequest ao IdP -> 302 com samlRequestId no 'forward'
        _dbg("passo 1: POST SAMLRequest ao Fluig (receiveSSORequest)")
        r1 = c.post(action1, data=inputs1, follow_redirects=False)
        location = r1.headers.get("location", "")
        saml_request_id = self._extract_saml_request_id(location)
        if not saml_request_id:
            raise LoginError(
                f"passo 1 falhou: samlRequestId nao encontrado (status {r1.status_code}, "
                f"location={location[:120]!r})."
            )
        _dbg(f"passo 1 OK: samlRequestId={saml_request_id[:12]}...")

        # -- Passo 2: login com senha -> 403 + mfa_token
        _dbg("passo 2: POST login (senha)")
        r2 = c.post(
            FLUIG_BASE + FLUIG_LOGIN_PATH,
            data={
                "domain": FLUIG_DOMAIN,
                "grant_type": "password",
                "username": username,
                "password": password,
                "captchaReturnedValue": "",
            },
            headers={"content-type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
        j2 = self._safe_json(r2)
        _dbg(f"passo 2: status={r2.status_code} shape={_describe(j2)}")
        mfa_token = _find_key(j2, "mfa_token", "mfatoken", "mfa")  # confirmado: campo `mfa_token`
        if not mfa_token:
            # captcha exigido? credenciais erradas? Mensagem sanitizada.
            raise LoginError(
                f"passo 2 falhou: mfa_token nao retornado (status {r2.status_code}). "
                "Verifique usuario/senha ou se ha captcha. Rode o probe pra inspecionar."
            )
        _dbg("passo 2 OK: mfa_token obtido")

        # -- Passo 3: troca MFA/TOTP -> sessao Fluig (cookies) + access_token
        _dbg("passo 3: POST token (MFA/TOTP)")
        totp = _totp_now(seed)
        r3 = c.post(
            FLUIG_BASE + FLUIG_TOKEN_PATH,
            data={
                "grant_type": FLUIG_MFA_TOTP_GRANT,
                "mfa_token": mfa_token,
                "totp_token": totp,
            },
            headers={"content-type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
        if r3.status_code >= 400:
            raise LoginError(
                f"passo 3 falhou: token MFA rejeitado (status {r3.status_code}). "
                "Seed TOTP incorreto ou codigo expirado."
            )
        j3 = self._safe_json(r3)
        _dbg(f"passo 3: status={r3.status_code} shape={_describe(j3)}")
        access_token = _find_key(j3, "access_token", "accesstoken")
        refresh_token = _find_key(j3, "refresh_token", "refreshtoken")
        if not access_token:
            raise LoginError("passo 3 falhou: access_token nao retornado apos MFA.")

        # *** Ponto NAO-obvio (confirmado ao vivo) ***
        # O SPA Angular do Fluig grava `access_token`/`refresh_token` como COOKIE
        # via document.cookie (JS) apos o MFA — e o cloudpass usa esse cookie pra
        # reconhecer a sessao no `receiveSSORequest`. Nenhuma resposta HTTP manda
        # Set-Cookie; e puramente client-side. Como httpx nao executa JS, setamos
        # os cookies manualmente aqui. SEM isso, o passo 4 volta pra tela de login.
        fluig_host = urlparse(FLUIG_BASE).netloc
        self._http.cookies.set("access_token", access_token, domain=fluig_host, path="/")
        if refresh_token:
            self._http.cookies.set("refresh_token", refresh_token, domain=fluig_host, path="/")
        _dbg("passo 3 OK: cookies access_token/refresh_token setados no Fluig")

        # -- Passo 4: retoma o SSO autenticado -> HTML com SAMLResponse
        _dbg("passo 4: GET receiveSSORequest autenticado (SAMLResponse)")
        r4 = c.get(action1, params={"samlRequestId": saml_request_id})
        action2, inputs2 = _parse_auto_post_form(r4.text)
        if not action2 or "SAMLResponse" not in inputs2:
            raise LoginError(
                "passo 4 falhou: nao achei o form SAMLResponse "
                f"(status {r4.status_code}, len {len(r4.text)}). "
                "Cookie access_token pode nao ter sido aceito pelo cloudpass."
            )
        _dbg(f"passo 4 OK: IdP->SP action={action2} inputs={list(inputs2)}")

        # -- Passo 5: POST ACS -> 302 + cookie de sessao do portal
        _dbg("passo 5: POST ACS (SAMLResponse) ao portal")
        r5 = c.post(action2, data=inputs2, follow_redirects=False)
        if r5.status_code not in (200, 302, 303):
            raise LoginError(f"passo 5 falhou: ACS status {r5.status_code}.")
        _dbg(f"passo 5 OK: ACS status={r5.status_code} (sessao do portal estabelecida)")

        # -- Passo 6: jwt/create -> token de tickets (JWT Zendesk ~13h)
        _dbg("passo 6: GET jwt/create")
        r6 = c.get(PORTAL_BASE + JWT_CREATE_PATH)
        token = (r6.text or "").strip().strip('"')
        if r6.status_code != 200 or token.count(".") != 2:
            raise LoginError(
                f"passo 6 falhou: jwt/create status {r6.status_code}, "
                f"resposta nao parece JWT (len {len(token)})."
            )
        _dbg("passo 6 OK: token de tickets obtido")
        return token

    @staticmethod
    def _extract_saml_request_id(location: str) -> str | None:
        """Extrai samlRequestId do Location do passo 1 (dentro do param 'forward')."""
        if not location:
            return None
        q = parse_qs(urlparse(location).query)
        # tenta direto
        if "samlRequestId" in q:
            return q["samlRequestId"][0]
        fwd = q.get("forward", [""])[0]
        if fwd:
            fq = parse_qs(urlparse(fwd).query)
            if "samlRequestId" in fq:
                return fq["samlRequestId"][0]
        # fallback bruto
        import re

        m = re.search(r"samlRequestId%3D([0-9a-fA-F-]+)", location) or re.search(
            r"samlRequestId=([0-9a-fA-F-]+)", location
        )
        return m.group(1) if m else None

    @staticmethod
    def _safe_json(r: httpx.Response) -> Any:
        try:
            return r.json()
        except Exception:
            return {}

    # ------------------------------------------------------------------ API tickets
    def post_ticket(
        self, path: str, payload: dict[str, Any] | None = None, *, inject_customer: bool = True
    ) -> Any:
        """POST read-only na API de tickets (ti-services), injetando token+customerCode.

        `path` deve comecar com `/` e ja incluir o prefixo apos TI_PREFIX, ou ser
        um caminho relativo ao `/customer-portal-backend`. Ver server.py.
        """
        self._ensure_token()
        full = path if path.startswith("http") else (TI_BASE + TI_PREFIX + path)
        attempt = 0
        while True:
            body = dict(payload or {})
            body["token"] = self._token
            if inject_customer and "customerCode" not in body:
                body["customerCode"] = self.default_customer_code
            r = self._http.post(
                full, params={"language": "pt"}, json=body, headers=_TI_HEADERS
            )
            if r.status_code in (401, 403) and attempt == 0:
                _dbg(f"ti-services {r.status_code} -> re-login e retry")
                self.login()
                attempt += 1
                continue
            _audit("POST", urlparse(full).path, r.status_code)
            r.raise_for_status()
            try:
                return r.json()
            except Exception:
                return {"_raw": r.text}

    def get_ti(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET read-only na API de tickets (poucos endpoints usam GET, ex: knowledge-base)."""
        self._ensure_token()
        full = path if path.startswith("http") else (TI_BASE + TI_PREFIX + path)
        p = dict(params or {})
        p.setdefault("language", "pt")
        attempt = 0
        while True:
            r = self._http.get(full, params=p, headers=_TI_HEADERS)
            if r.status_code in (401, 403) and attempt == 0:
                self.login()
                attempt += 1
                continue
            _audit("GET", urlparse(full).path, r.status_code)
            r.raise_for_status()
            try:
                return r.json()
            except Exception:
                return {"_raw": r.text}
