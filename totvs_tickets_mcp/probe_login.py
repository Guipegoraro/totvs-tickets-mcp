"""Probe do fluxo de login (reverse-engineering ao vivo, seguro).

Roda a cadeia completa Fluig -> MFA/TOTP -> SAML -> ACS -> jwt/create com
logging VERBOSO e REDIGIDO (valores sensiveis viram `<str:len>`), pra confirmar
os poucos nomes de campo de resposta que nao estavam nos HARs (ex: como o
`mfa_token` volta) e diagnosticar qualquer passo que quebre (WAF, captcha, seed).

Uso:
    totvs-tickets-probe
    # ou:
    python -m totvs_tickets_mcp.probe_login

Requer credenciais ja cadastradas (`totvs-tickets-setup`) OU as variaveis
TOTVS_USERNAME / TOTVS_PASSWORD / TOTVS_TOTP_SEED no ambiente.

O que imprimir de volta pro dev: TODO o texto do terminal (inclui stderr). Ele
NAO contem senha nem token em claro — so o FORMATO das respostas.
"""

from __future__ import annotations

import os
import sys


def main(argv: list[str] | None = None) -> int:
    # Forca debug verboso e desliga o cache pra sempre exercitar o fluxo inteiro.
    os.environ["TOTVS_DEBUG"] = "1"
    os.environ["TOTVS_NO_TOKEN_CACHE"] = "1"

    print("=" * 70)
    print("PROBE DE LOGIN — Portal do Cliente TOTVS")
    print("Roda a cadeia SAML+MFA e imprime o FORMATO das respostas (sem segredos).")
    print("Copie TODA a saida abaixo (incluindo linhas [totvs-tickets]) pro dev.")
    print("=" * 70)

    from .client import LoginError, TotvsTicketsClient

    try:
        client = TotvsTicketsClient()
    except RuntimeError as e:
        print(f"\nSem credenciais: {e}")
        print("Rode `totvs-tickets-setup` ou defina TOTVS_USERNAME/PASSWORD/TOTP_SEED.")
        return 2

    try:
        client.login()
    except LoginError as e:
        print(f"\n>>> LOGIN FALHOU num passo do fluxo: {e}")
        print(">>> A(s) linha(s) [totvs-tickets] acima mostram onde e o formato observado.")
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"\n>>> ERRO inesperado: {type(e).__name__}: {e}")
        return 1

    print("\n>>> LOGIN OK — cadeia completa funcionou.")
    print(f"    userId (zendesk):    {client.user_id}")
    print(f"    customerCode padrao: {client.default_customer_code}")
    print(f"    org primaria:        {client.primary_org_id}")
    print("    organizacoes:")
    for o in client.organizations:
        print(f"      - {o['external_id']}  {o['name']}  (id {o['id']})")
    print("\n    Claims do token (chaves de topo):", list(client.claims.keys()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
