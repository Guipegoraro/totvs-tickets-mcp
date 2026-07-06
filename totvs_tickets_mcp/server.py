"""MCP server read-only do Portal do Cliente TOTVS (suporte.totvs.com).

Expoe os tickets de suporte da TOTVS como tools read-only. Cada tool e fina:
monta o body no formato exato do portal e delega ao `TotvsTicketsClient`, que
resolve auth (Fluig + MFA/TOTP + SAML), cache do token e injecao de
`token`/`customerCode`.
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .client import TotvsTicketsClient

# Organizacao padrao da BUSCA de tickets (nao a org do usuario). Configuravel por
# env `TOTVS_DEFAULT_ORG` pra manter o MCP generico. Se vazio, a busca varre TODAS
# as orgs visiveis (organizationsIds=[]). Dica: a org "primaria"/pessoal do usuario
# costuma vir VAZIA — configure aqui o id (Zendesk) da org que concentra os
# chamados; pegue os ids disponiveis via `totvs_whoami`.
_DEFAULT_SEARCH_ORG = os.environ.get("TOTVS_DEFAULT_ORG", "").strip()

_INSTRUCTIONS = """Servidor MCP read-only do Portal do Cliente TOTVS (suporte.totvs.com) — tickets de suporte da TOTVS (Central de Atendimento).

ESCOPO: somente leitura. Lista, filtra e le detalhes/comentarios de tickets. Nao cria, nao atualiza, nao fecha.

Autenticacao: automatica (Fluig Identity com senha + MFA/TOTP -> SAML SSO -> jwt/create). O token de tickets dura ~13h e fica cacheado cifrado; o primeiro uso (ou apos expirar) faz a danca de login, que leva alguns segundos. Se o login falhar, a tool retorna erro pedindo `totvs-tickets-setup`/`totvs-tickets-probe`.

Convencoes (load-bearing):

1. BUSCA de tickets e por ORGANIZACAO, nao por "meus tickets". IMPORTANTE: a org PRIMARIA/pessoal do usuario normalmente retorna VAZIO — nao e onde os chamados estao. Por padrao, `totvs_tickets_listar` busca na org configurada (env TOTVS_DEFAULT_ORG) ou, se nao configurada, em TODAS as orgs visiveis. Para escopar, passe `organization_ids` com os ids desejados; passe `organization_ids=[]` (lista vazia) pra buscar em TODAS as orgs. Veja as orgs disponiveis (e seus ids) com `totvs_whoami`. A busca ve tickets de qualquer solicitante da org (nao so os do usuario), casando por `keywords` no titulo/numero/conteudo.

2. Status de ticket (valores do filtro `status` em `totvs_tickets_listar`): lista oficial confirmada via `totvs_tickets_status`: `new_open_hold` = Aberto, `pending` = Pendente cliente, `solved` = Validacao cliente, `closed` = Fechado. Se a TOTVS adicionar/alterar valores, `totvs_tickets_status` e a fonte da verdade.

3. Formato de data dos filtros (`created_start`/`created_end`/`updated_start`/`updated_end`): ainda NAO confirmado (veio vazio no HAR). Trate como hipotese; se um filtro de data nao funcionar como esperado, avise o usuario que o formato precisa ser confirmado em vez de insistir.

4. Hipotese vs fato: ao inferir o significado de um campo/codigo nao documentado da resposta, trate como HIPOTESE e sinalize ao usuario. Nao codifique interpretacao como verdade.

5. Ao citar um ticket, inclua o numero (`ticketId`). NAO invente URL de ticket — o padrao de URL da tela de detalhe do portal nao foi confirmado; se precisar, oriente o usuario a abrir pelo portal.

6. `ticket_views` em `totvs_tickets_listar` (load-bearing, semantica confirmada pelo usuario): `1` = meus tickets (abertos por mim), `2` = tickets em que estou em copia, `3` = tickets criados por OUTROS usuarios da org (DEFAULT, e onde esta o volume). Sao conjuntos DISJUNTOS — se o usuario pedir "todos os meus envolvimentos", consulte as 3 visoes e una. Buscas por assunto/numero geralmente usam `3`.
"""


def _ro(title: str) -> ToolAnnotations:
    """Annotation de tool read-only que consulta a API externa da TOTVS."""
    return ToolAnnotations(
        title=title,
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    )


mcp = FastMCP("totvs-tickets", instructions=_INSTRUCTIONS)

_client: TotvsTicketsClient | None = None


def _client_ref() -> TotvsTicketsClient:
    global _client
    if _client is None:
        _client = TotvsTicketsClient()
    return _client


# --- Perfil / contato -----------------------------------------------------
@mcp.tool(annotations=_ro("Perfil do usuario logado"))
def totvs_whoami() -> dict[str, Any]:
    """Identidade do usuario no portal TOTVS derivada do token: userId Zendesk,
    customerCode padrao, organizacoes as quais pertence e validade do token.
    Use pra descobrir os `organization_ids`/`customerCode` disponiveis."""
    c = _client_ref()
    c._ensure_token()
    return {
        "userId": c.user_id,
        "email": c.claims.get("email"),
        "customerCode_padrao": c.default_customer_code,
        "org_primaria": c.primary_org_id,
        "organizacoes": c.organizations,
        "token_exp": c._exp,
    }


@mcp.tool(annotations=_ro("Dados do contato logado"))
def totvs_contato() -> dict[str, Any]:
    """Dados cadastrais do contato logado no portal (nome, email, telefone,
    empresa/customerCode, cargo). Endpoint contact/find-contact."""
    return _client_ref().post_ticket("/contact/find-contact")


# --- Tickets --------------------------------------------------------------
@mcp.tool(annotations=_ro("Listar tickets"))
def totvs_tickets_listar(
    keywords: str = "",
    status: list[str] | None = None,
    product_tags: list[str] | None = None,
    module_tags: list[str] | None = None,
    routine_tags: list[str] | None = None,
    organization_ids: list[str] | None = None,
    requester_id: str = "",
    created_start: str = "",
    created_end: str = "",
    updated_start: str = "",
    updated_end: str = "",
    page: int = 1,
    sort_by: str = "updated_at",
    sort_order: str = "desc",
    ticket_views: int = 3,
) -> dict[str, Any]:
    """Busca/lista tickets de suporte TOTVS por ORGANIZACAO, com filtros e paginacao.

    A busca ve tickets de qualquer solicitante da(s) organizacao(oes) — nao so os
    do usuario logado. `keywords` casa por numero, titulo e conteudo.

    - keywords: texto livre (numero do ticket, palavra do titulo/descricao/comentario).
    - status: lista de valores (ver `totvs_tickets_status`). None/[] = todos.
    - product_tags / module_tags / routine_tags: tags do catalogo (ver `totvs_tickets_filtros`).
      Ex Protheus: product_tags=['cattotvs_nivel_3_linha_protheus'].
    - organization_ids: IDs de org (ver `totvs_whoami`). None = org padrao (env
      TOTVS_DEFAULT_ORG, ou todas se nao configurada). `[]` = TODAS as orgs visiveis.
      ATENCAO: a org primaria/pessoal do usuario costuma retornar VAZIO; configure
      a org que concentra os chamados via TOTVS_DEFAULT_ORG (id via `totvs_whoami`).
    - requester_id: filtra por solicitante.
    - created_start/created_end/updated_start/updated_end: filtros de data (formato a confirmar).
    - page: pagina (1-based).
    - sort_by: campo de ordenacao (default `updated_at`). sort_order: `asc`/`desc`.
    - ticket_views: qual VISAO/aba de tickets (load-bearing, semantica confirmada
      pelo usuario): `1` = meus tickets (abertos por mim); `2` = tickets em que
      estou em copia (colaborador); `3` = tickets criados por OUTROS usuarios da
      org (default — e onde esta o volume). Sao conjuntos DISJUNTOS: pra cobrir
      tudo, consulte as 3 visoes e una os resultados. Nesta conta, `1` e `2`
      costumam vir vazios; a busca util fica em `3`.
    """
    c = _client_ref()
    c._ensure_token()
    if organization_ids is not None:
        org_ids = organization_ids
    elif _DEFAULT_SEARCH_ORG:
        org_ids = [_DEFAULT_SEARCH_ORG]
    else:
        org_ids = []  # todas as orgs visiveis
    body = {
        "keywords": keywords or "",
        "updatedAtStart": updated_start or "",
        "updatedAtEnd": updated_end or "",
        "createdAtStart": created_start or "",
        "createdAtEnd": created_end or "",
        "catalogV3ProductTags": product_tags or [],
        "catalogV3ModuleTags": module_tags or [],
        "catalogV3RoutineGrouperTags": routine_tags or [],
        "organizationsIds": org_ids,
        "requesterId": requester_id or "",
        "isTechnicalConsultancy": None,
        "status": status or [],
        "ticketViews": ticket_views,
        "primeRhodium": 0,
        "userId": c.user_id,
        "pagination": {"page": page},
        "sortBy": sort_by,
        "sortOrder": sort_order,
    }
    return c.post_ticket("/help-center/tickets/get-tickets", body)


@mcp.tool(annotations=_ro("Detalhe do ticket"))
def totvs_ticket_detalhe(ticket_id: str) -> dict[str, Any]:
    """Detalhe completo de um ticket (solicitante, colaboradores, organizacao,
    status, produto/modulo, etc). `ticket_id` = numero do ticket (ex: '29586485')."""
    return _client_ref().post_ticket(
        "/help-center/tickets/get-ticket", {"ticketId": str(ticket_id)}
    )


@mcp.tool(annotations=_ro("Comentarios/andamentos do ticket"))
def totvs_ticket_comentarios(
    ticket_id: str, page: int = 1, sort_order: str = "DESC"
) -> dict[str, Any]:
    """Comentarios/andamentos de um ticket, com anexos. `ticket_id` = numero do
    ticket. `sort_order`: 'DESC' (mais recentes primeiro) ou 'ASC'."""
    return _client_ref().post_ticket(
        "/help-center/tickets/get-comments",
        {"ticketId": str(ticket_id), "pagination": {"page": page, "sortOrder": sort_order}},
    )


# --- Metadados de filtro --------------------------------------------------
@mcp.tool(annotations=_ro("Status disponiveis para filtro"))
def totvs_tickets_status() -> Any:
    """Lista oficial de status usaveis no filtro `status` de `totvs_tickets_listar`
    (value + label). Ex: {value:'new_open_hold', label:'Aberto'}."""
    return _client_ref().post_ticket("/help-center/tickets/get-tickets/filter-status")


@mcp.tool(annotations=_ro("Opcoes de filtro (produto/modulo/rotina)"))
def totvs_tickets_filtros(
    tipo: str, filtro: str = "", page: int = 1, page_size: int = 10
) -> Any:
    """Opcoes do catalogo para os filtros de `totvs_tickets_listar`.

    - tipo: 'product', 'module' ou 'routine'.
    - filtro: texto pra buscar dentro das opcoes (vazio = primeiras).
    - page / page_size: paginacao.
    Retorna itens com as tags usadas em product_tags/module_tags/routine_tags.
    """
    t = (tipo or "").strip().lower()
    if t not in ("product", "module", "routine"):
        raise ValueError("tipo invalido: use 'product', 'module' ou 'routine'.")
    return _client_ref().post_ticket(
        f"/help-center/tickets/filter/lookup/{t}/get-filtered-items",
        {"filter": filtro or "", "page": page, "pageSize": page_size},
    )


@mcp.tool(annotations=_ro("Motivos de priorizacao"))
def totvs_tickets_motivos_prioridade() -> Any:
    """Lista de motivos de priorizacao (priority-reasons) usados no portal."""
    return _client_ref().post_ticket(
        "/help-center/tickets/priority-reasons", {"platformCode": None}
    )


# --- Outros (mapeados do portal) -----------------------------------------
@mcp.tool(annotations=_ro("Contagem de notificacoes nao lidas"))
def totvs_notificacoes_count() -> dict[str, Any]:
    """Numero de notificacoes nao lidas do usuario no portal (ex: {'unread': 44})."""
    return _client_ref().post_ticket("/user-notifications/count")


@mcp.tool(annotations=_ro("Buscar usuarios/contatos"))
def totvs_usuarios_buscar(termo: str, organization_ids: list[str] | None = None) -> Any:
    """Busca usuarios/contatos do Zendesk por termo (nome/email), opcionalmente
    escopado por organizacao. Util pra descobrir o `requester_id` de alguem.

    - termo: minimo 3 caracteres (a API rejeita menos).
    - organization_ids: IDs de org (None/[] = todas as visiveis).
    """
    if len((termo or "").strip()) < 3:
        raise ValueError("termo muito curto: a busca exige no minimo 3 caracteres.")
    return _client_ref().post_ticket(
        "/help-center/users/get-users-zendesk-by-term-and-organizations",
        {"term": termo.strip(), "organizationsIds": organization_ids or []},
    )


@mcp.tool(annotations=_ro("Departamentos de atendimento"))
def totvs_departamentos() -> Any:
    """Lista os departamentos/areas de atendimento do portal (key, label, nome,
    tags). Endpoint chats-departaments/get-departament-by-area."""
    return _client_ref().post_ticket(
        "/help-center/chats-departaments/get-departament-by-area"
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
