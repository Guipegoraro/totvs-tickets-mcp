# totvs-tickets-mcp

Servidor **MCP (Model Context Protocol)** local, **somente leitura**, que expoe os
**tickets de suporte da TOTVS** (Portal do Cliente / Central de Atendimento,
`suporte.totvs.com`) como tools para LLMs no Claude Code, Claude Desktop e Cursor.

Escrito em **Python**, mesmo molde do [`tspace-mcp`](../tspace-mcp): keyring nativo
do OS pra credenciais, cache de token cifrado (Fernet), headers de browser e
re-login transparente.

> Escopo: **read-only**. Lista, filtra e le tickets/comentarios. Nao cria, nao
> atualiza, nao fecha chamados.

## Como autentica (o ponto nao-obvio)

O portal da TOTVS **nao** usa um bearer/cookie simples. A cadeia e:

```
Fluig Identity (usuario + senha + MFA/TOTP)  ->  SAML SSO  ->  sessao no portal
                                                                    |
                          GET .../portal/jwt/create  ->  token (JWT Zendesk, ~13h)
                                                                    |
   ti-services.totvs.com.br/customer-portal-backend/help-center/tickets/*
                          (o token vai no BODY do POST, nao em header)
```

O `client.py` replica isso automaticamente (login com senha, gera o codigo TOTP a
partir do seed do autenticador, faz a danca SAML, emite o token). O token de ~13h
fica cacheado cifrado em `~/.totvs-tickets-mcp-token.json`, entao a danca so
acontece ~1x por turno de trabalho.

## Instalacao

```bash
pip install -e .          # le pyproject.toml (mcp, httpx, keyring, cryptography, pyotp)
```

Isso instala os comandos `totvs-tickets-mcp`, `totvs-tickets-setup` e
`totvs-tickets-probe` em `<python>/Scripts/`.

## Configuracao (primeira vez)

```bash
totvs-tickets-setup
```

Pede tres coisas, guardadas no keyring do OS (servico `totvs-tickets-mcp`):

| Segredo    | O que e                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| Username   | login Fluig (ex: `nome.sobrenome`)                                       |
| Senha      | senha do acesso TOTVS                                                    |
| Seed TOTP  | a **chave secreta base32** do app autenticador (a que aparece em "inserir manualmente" ao cadastrar o MFA) |

> O seed TOTP e o que permite gerar o codigo de 6 digitos sem o app. Se voce so
> tem o app e nao guardou o seed, precisa **re-cadastrar o MFA** no Fluig pra
> obter um seed novo (o app e este MCP passam a usar o mesmo seed).

Depois, teste o login de ponta a ponta:

```bash
totvs-tickets-setup --test      # loga e imprime seu userId / customerCode / organizacoes
totvs-tickets-setup --show      # mostra o que esta cadastrado (mascarado)
totvs-tickets-setup --remove    # apaga tudo
```

Se o login falhar, rode o **probe** (diagnostico verboso e seguro):

```bash
totvs-tickets-probe
```

Ele executa a cadeia inteira imprimindo apenas o **formato** das respostas
(segredos redigidos como `<str:len>`), revelando onde quebrou (WAF, captcha,
seed) ou confirmando os nomes de campo do fluxo.

## Registrar no Claude Code

```bash
claude mcp add -s user totvs-tickets -- totvs-tickets-mcp
```

Apos editar `client.py`/`server.py`, **reinicie a sessao** do Claude Code (o MCP
roda em processo persistente e nao recarrega sozinho).

### Um processo para varias sessoes (`--http`)

Em stdio, cada sessao do Claude Code sobe o proprio processo e faz o proprio
login SAML/MFA. Com `--http`, um processo so atende todas as sessoes por
streamable HTTP, com um login e um token de tickets:

```bash
totvs-tickets-mcp --http --port 47103 --token-file C:/caminho/token
```

- Escuta so em `127.0.0.1`.
- Toda requisicao precisa de `Authorization: Bearer <token>`, com o token do
  arquivo (minimo 32 caracteres). Sem ele: 401. Deixe o arquivo legivel so
  pelo seu usuario.
- Host e Origin que nao sejam locais sao recusados (protecao contra DNS
  rebinding do FastMCP).
- `TOTVS_DEFAULT_ORG` e as demais variaveis vao no ambiente do processo.
- O processo nao reinicia sozinho: rode-o por um gerenciador (tarefa agendada,
  servico) que o suba no logon e o reinicie se cair.

Registro no Claude Code, com o token enviado por `headersHelper` (comando que
imprime o JSON dos headers):

```bash
claude mcp add-json totvs-tickets -s user '{"type":"http","url":"http://127.0.0.1:47103/mcp","headersHelper":"node C:/caminho/headers.mjs"}'
```

As chamadas de sessoes diferentes sao atendidas uma por vez.

## Tools (todas read-only)

| Tool                              | Endpoint                                   | O que faz |
| --------------------------------- | ------------------------------------------ | --------- |
| `totvs_whoami`                    | (token)                                    | userId, customerCode, organizacoes, validade do token |
| `totvs_contato`                   | `contact/find-contact`                     | dados cadastrais do contato logado |
| `totvs_tickets_listar`            | `tickets/get-tickets`                       | **busca** por org + `ticket_views` (status, datas, produto/modulo/rotina, keywords) + paginacao |
| `totvs_ticket_detalhe`            | `tickets/get-ticket`                        | detalhe de um ticket |
| `totvs_ticket_comentarios`        | `tickets/get-comments`                      | andamentos/comentarios (com anexos) |
| `totvs_tickets_status`            | `tickets/get-tickets/filter-status`         | lista oficial de status (value+label) |
| `totvs_tickets_filtros`           | `tickets/filter/lookup/{tipo}`              | opcoes de produto/modulo/rotina pro filtro |
| `totvs_tickets_motivos_prioridade`| `tickets/priority-reasons`                  | motivos de priorizacao |
| `totvs_notificacoes_count`        | `user-notifications/count`                  | qtd de notificacoes nao lidas |
| `totvs_usuarios_buscar`           | `users/get-users-zendesk-by-term...`        | busca usuarios/contatos por termo (min 3 chars) |
| `totvs_departamentos`             | `chats-departaments/get-departament-by-area`| departamentos/areas de atendimento |

> **Busca de tickets** (load-bearing): a org primaria/pessoal do usuario costuma
> vir VAZIA — configure a org que concentra os chamados via `TOTVS_DEFAULT_ORG`
> (id via `totvs_whoami`). E `ticket_views=3` (default) = tickets de outros; `1` =
> meus, `2` = em copia. Ver `CLAUDE.md`.

## Variaveis de ambiente uteis

- `TOTVS_USERNAME` / `TOTVS_PASSWORD` / `TOTVS_TOTP_SEED` — override do keyring.
- `TOTVS_DEFAULT_ORG` — org padrao da busca (id Zendesk da org; veja via `totvs_whoami`). Vazio = todas as orgs visiveis.
- `TOTVS_DEBUG=1` — log verboso do login em stderr (formato das respostas).
- `TOTVS_NO_TOKEN_CACHE=1` — desliga o cache de token em disco.
- `TOTVS_AUDIT_LOG=1` — apende timestamp+verbo+path+status em `~/.totvs-tickets-mcp-audit.log`.
- `TOTVS_TIMEOUT` — timeout de request em segundos (default 60).

## Arquivos sensiveis (nao commitar)

`.gitignore` bloqueia `*.har`, `.totvs-tickets-mcp-token.json`, `*.env`, chaves.
O login usa credenciais reais — nunca capture o HAR do login sem cuidado (o
request de senha vaza a senha em texto puro; ver `docs`/CLAUDE.md).

## Estado

**Funcionando** (validado ponta a ponta em 03/07/2026): login automatico
Fluig+MFA/TOTP+SAML, cache do token, e as tools `totvs_tickets_listar`,
`totvs_ticket_detalhe`, `totvs_ticket_comentarios`, `totvs_tickets_status`,
`totvs_contato`, `totvs_whoami` retornando dados reais.

Detalhe nao-obvio do login (o SPA seta o `access_token` como cookie via JS, que o
cloudpass usa pra continuar o SSO) esta documentado em `CLAUDE.md`.

O esqueleto TypeScript anterior deste projeto esta arquivado em `archive-ts/`.
