# CLAUDE.md

Guia pra Claude Code trabalhando neste repositorio.

## O que e este projeto

MCP server local em Python que expoe os **tickets de suporte da TOTVS** (Portal
do Cliente, `suporte.totvs.com`) como **tools read-only** pra LLMs. Mesmo molde
do `tspace-mcp` (keyring, cache cifrado com Fernet, headers de browser).

**Read-only e escopo deliberado.** Nao ha tools de escrita. Se um dia houver,
elas exigem autorizacao expressa por chamada (padrao do tspace) e revisao antes.

## ⚠ Regra de seguranca: HAR do login vaza a senha

O `POST /api/auth/v1/login` do Fluig manda a senha em **texto puro** no body
(`password=...`). Qualquer HAR que capture o login contem a senha em claro.
- Nunca commitar `.har` (ja no `.gitignore`).
- Ao pedir HAR pro usuario, avisar pra trocar a senha depois / apagar o `.har`.
- Preferir o `totvs-tickets-probe` (nao grava nada, redige segredos) a pedir HAR.

## ⚠ Hipotese vs fato (load-bearing)

O portal retorna varios codigos/enums sem dicionario (status como
`new_open_hold`, flags de organizacao). Ao inferir significado sem evidencia
(HAR, doc oficial, observacao reproduzivel), trate como **hipotese** — nao
afirme ao usuario nem codifique como verdade em docstring/pos-processamento.

Codigos com semantica observada (mas confirmar via tool quando possivel):
- Status de ticket (filtro): `new_open_hold`=Aberto, `pending`=Pendente cliente,
  `solved`=Validacao cliente. Lista oficial: `totvs_tickets_status`.

## Arquitetura

```
Cliente MCP (stdio) <-> server.py <-> TotvsTicketsClient (client.py) <-> HTTPS
                                             |
                     keyring do OS (user/senha/seed TOTP)  +  cache Fernet do token de 13h
```

### Fluxo de auth (essencial pra debug) — client.py `_run_saml_login`

SP-initiated SAML com MFA/TOTP. 7 passos, um cookie jar httpx compartilhado:

0. `GET suporte.totvs.com/.../dashboard/tickets` -> HTML com form auto-post (SAMLRequest).
1. `POST` esse form ao Fluig (`cloudpass/.../receiveSSORequest`) -> 302 com `samlRequestId` no `forward`.
2. `POST /api/auth/v1/login` (domain=totvs, grant_type=password, user, senha, captchaReturnedValue="") -> **403 + mfa_token**.
3. `POST /api/auth/v1/token` (grant_type=`http://fluigidentity.com/api/mfa/totp`, mfa_token, totp_token) -> 200, sessao Fluig (cookies).
4. `GET receiveSSORequest?samlRequestId=X` -> HTML com form auto-post (SAMLResponse).
5. `POST suporte.totvs.com/portal/idp/ACS` (SAMLResponse, RelayState) -> 302, sessao do portal (cookies).
6. `GET .../portal/jwt/create` -> **token** (JWT Zendesk HS256, ~13h). Cacheado cifrado.

O token final vai no **body** (`token` + `customerCode`) de cada POST em
`ti-services.totvs.com.br/customer-portal-backend/...`. NAO ha header de auth
nessas chamadas — so headers de browser (origin/referer).

### O ponto NAO-obvio do login (CONFIRMADO ao vivo, 03/07/2026)

Os HARs originais nao tinham os *corpos de resposta* do login. Foram confirmados
rodando o login real (`totvs-tickets-probe` / diagnosticos ao vivo):

- **`mfa_token`** (passo 2, resposta 403): campo `mfa_token` (junto de `company_id`,
  `mfa_authentication_by_email_enabled`). Extraido via `_find_key`.
- **`access_token`/`refresh_token`** (passo 3, resposta 200): campos `access_token`,
  `refresh_token`, `expires_in` (600s), `token_type`.
- **O pulo do gato:** o IdP Fluig **nao seta NENHUM cookie** via HTTP. O SPA Angular
  grava `access_token`/`refresh_token` como cookie via `document.cookie` (JS,
  `cookieService`), e o **cloudpass usa esse cookie** pra reconhecer a sessao no
  `receiveSSORequest` (passo 4). Como httpx nao roda JS, o `client.py` **seta esses
  cookies manualmente** no dominio `totvs.fluigidentity.com` apos o passo 3. SEM
  isso, o passo 4 volta 302 pra tela de login e a cadeia quebra. Descoberto
  grepando o `main.<hash>.js` do SPA (`this.cookieService.get("access_token")`).

Login validado ponta a ponta: passos 0-6 OK, token de tickets emitido e cacheado.
`get-tickets`, `get-ticket`, `get-comments`, `filter-status`, `contact/find-contact`
retornam dados reais.

### Riscos conhecidos do login automatico

- **WAF/anti-bot** (CloudFront/AWS WAF na frente do portal): se o passo 0 nao
  retornar o form SAMLRequest, pode ser challenge de bot — httpx "nu" nao passa.
  Mitigacao atual: `_BROWSER_HEADERS`. Plano B: `curl_cffi` (fingerprint TLS).
- **Captcha**: o login manda `captchaReturnedValue=""`. Se a TOTVS ligar captcha
  por risco, o passo 2 falha — nao ha automacao possivel sem intervencao.
- **Fragilidade SAML**: mudanca no IdP/portal quebra o parsing dos forms.

## Como rodar / testar

```
pip install -e .                 # instala + deps (inclui pyotp)
totvs-tickets-setup              # cadastra user/senha/seed TOTP
totvs-tickets-setup --test       # loga e imprime customerCode/orgs
totvs-tickets-probe              # diagnostico verboso do login (redigido)
claude mcp add -s user totvs-tickets -- totvs-tickets-mcp
```

Nao ha test suite. Validacao e end-to-end. Testes estaticos seguros (sem rede):
importar `server`/`client`, `server.mcp.list_tools()`, e as funcoes puras
(`_parse_auto_post_form`, `_extract_saml_request_id`, `_find_key`, `_describe`).

**NUNCA** dispare o login real em "smoke test" sem que o usuario tenha cadastrado
credenciais e sabendo que consome um codigo TOTP e bate no portal real.

**Apos editar `client.py`/`server.py`, reinicie a sessao do Claude Code** (MCP e
processo persistente).

## Convencoes da BUSCA de tickets (load-bearing — descoberto 03/07/2026)

A busca (`get-tickets` / tool `totvs_tickets_listar`) NAO e "meus tickets" — e por
organizacao e por VISAO. Dois campos decidem se ela retorna algo:

- **`ticketViews`** (seletor de visao, semantica confirmada pelo usuario):
  `1` = meus tickets (abertos por mim), `2` = tickets em que estou em copia,
  `3` = tickets criados por OUTROS usuarios da org. **Default `3`** — e onde esta
  o volume. Conjuntos DISJUNTOS. Com `ticketViews` ausente/1/2 a busca desta conta
  vem VAZIA. Foi o campo que faltava (a tool dava 0 sem ele).
- **`organizationsIds`**: a org PRIMARIA/pessoal do usuario costuma retornar VAZIO
  — os chamados ficam numa OUTRA org (aquela que concentra o volume). `[]` = todas
  as orgs visiveis. Default configuravel por env **`TOTVS_DEFAULT_ORG`** (id Zendesk
  da org; pegue via `totvs_whoami`); se vazio, busca em todas.
- Arrays de filtro vazios devem ser `[]`, **nao** `[""]` (o `[""]` do dashboard
  difere do `[]` da busca). tags de produto: ex Linha Protheus =
  `catalogV3ProductTags: ["cattotvs_nivel_3_linha_protheus"]`.

Evidencia (capturas de HAR do portal): `ticketViews=3 org=[]` numa busca ampla ->
milhares; `ticketViews=3 org=<org com volume>` -> dezenas; `ticketViews=1` -> 0.

## Adicionando uma tool

1. Achar o endpoint no HAR do portal (ou no `archive-ts/scripts/analyze-har.mjs`).
2. Body: sempre POST em `ti-services.../customer-portal-backend/...` com `token`
   e `customerCode` — que o `client.post_ticket()` **injeta**; nao coloque na tool.
3. Manter **capitalizacao exata** dos campos do HAR (ex: `pageSize`, `organizationsIds`).
   Nao normalizar — e erro facil e silencioso (200 OK com dado errado).
4. Docstring curta em PT-BR (vira a description da tool). Annotation `_ro(...)`.
5. Reiniciar o cliente MCP.

## Arquivos

- `client.py` — auth (SAML+MFA+TOTP), cache Fernet, `post_ticket`/`get_ti`.
- `server.py` — FastMCP + tools read-only.
- `setup_credentials.py` — CLI de credenciais (`--show/--remove/--test`).
- `probe_login.py` — diagnostico verboso do login (reverse-engineering seguro).
- `run.py` — wrapper de fallback (ajusta sys.path).
- `archive-ts/` — esqueleto TypeScript anterior (arquivado, nao usar).
- `har/` — coloque `.har` aqui (gitignored).
