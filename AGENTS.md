# AGENTS.md — instrucoes para a LLM que consome este MCP

Guia de uso das tools do `totvs-tickets-mcp` por um agente/LLM (Claude, etc). O
proprio servidor injeta um resumo destas regras no handshake; este arquivo e a
versao completa e estavel. Regras marcadas **load-bearing** mudam o resultado se
ignoradas.

## O que este MCP faz

Expoe, como **tools read-only**, os tickets de suporte do **Portal do Cliente
TOTVS** (`suporte.totvs.com` / Central de Atendimento). Lista, filtra e le
detalhes/comentarios de tickets. **Nao cria, nao atualiza, nao fecha nada.**

Autenticacao e automatica (Fluig Identity: senha + MFA/TOTP -> SAML SSO ->
token de ~13h cacheado). A primeira chamada (ou apos o token expirar) faz o
login, que leva alguns segundos. Se faltar credencial/seed, a tool retorna erro
pedindo `totvs-tickets-setup`.

## Tools

| Tool | Use para |
|------|----------|
| `totvs_whoami` | Descobrir userId, organizacoes do usuario e seus **ids** (necessarios pra escopar buscas), validade do token. |
| `totvs_tickets_listar` | **Buscar/listar** tickets por organizacao + visao. Principal ferramenta de busca. |
| `totvs_ticket_detalhe` | Ler um ticket especifico pelo numero (`ticket_id`). Funciona mesmo pra tickets de outra org. |
| `totvs_ticket_comentarios` | Ler os andamentos/comentarios (com anexos) de um ticket. |
| `totvs_tickets_status` | Lista oficial de valores de status (para o filtro `status`). |
| `totvs_tickets_filtros` | Opcoes do catalogo (produto/modulo/rotina) para os filtros de tag. |
| `totvs_tickets_motivos_prioridade` | Motivos de priorizacao. |
| `totvs_contato` | Dados cadastrais do contato logado. |
| `totvs_usuarios_buscar` | Buscar pessoas/contatos por termo (min. 3 chars) — util pra achar `requester_id`. |
| `totvs_notificacoes_count` | Quantidade de notificacoes nao lidas. |
| `totvs_departamentos` | Departamentos/areas de atendimento. |

## Convencoes load-bearing

1. **Busca e por ORGANIZACAO, nao "meus tickets".** A org primaria/pessoal do
   usuario normalmente vem VAZIA. Por padrao `totvs_tickets_listar` usa a org
   configurada em `TOTVS_DEFAULT_ORG` ou, se nao houver, TODAS as orgs visiveis.
   Para escopar, passe `organization_ids` (ids via `totvs_whoami`);
   `organization_ids=[]` busca em todas. A busca ve tickets de **qualquer
   solicitante** da org, casando `keywords` em numero/titulo/conteudo.

2. **`ticket_views` (seletor de visao)** — semantica confirmada pelo dono do
   portal: `1` = tickets abertos por mim; `2` = tickets em que estou em copia;
   `3` = tickets criados por OUTROS usuarios da org (**default**, e onde esta o
   volume). Sao conjuntos DISJUNTOS. Buscas por assunto/numero geralmente usam
   `3`. Se o usuario pedir "tudo que me envolve", consulte as 3 visoes e una.

3. **Status** — use `totvs_tickets_status` como fonte da verdade. Valores
   observados: `new_open_hold` = Aberto, `pending` = Pendente cliente,
   `solved` = Validacao cliente, `closed` = Fechado.

4. **Formato de data dos filtros** (`created_*`/`updated_*`) ainda NAO foi
   confirmado. Trate como hipotese; se um filtro de data nao surtir efeito,
   avise o usuario em vez de insistir.

5. **Hipotese vs fato** — ao inferir o significado de um campo/codigo nao
   documentado da resposta, trate como HIPOTESE e sinalize. Nao apresente
   interpretacao como verdade.

6. **Ao citar um ticket**, inclua o numero (`ticketId`). NAO invente URL da tela
   de detalhe — o padrao nao foi confirmado; oriente o usuario a abrir pelo portal.

7. **Respostas podem ser grandes** (a listagem traz objetos aninhados por ticket).
   Ao responder ao humano, resuma (numero, assunto, status, produto/modulo,
   solicitante, datas) em vez de despejar o JSON cru; use `totvs_ticket_detalhe`/
   `totvs_ticket_comentarios` quando precisar de profundidade num ticket especifico.
