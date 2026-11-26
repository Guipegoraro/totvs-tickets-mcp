"""Cadastra/atualiza/remove credenciais do Portal TOTVS no keyring do OS.

Guarda tres segredos no servico keyring `totvs-tickets-mcp`:
  - username (login Fluig, ex: nome.sobrenome)
  - senha    (sob a chave = username)
  - seed TOTP (chave secreta base32 do app autenticador, pra gerar o codigo MFA)

Uso:
    totvs-tickets-setup            # cadastra ou atualiza
    totvs-tickets-setup --show     # mostra o que esta armazenado (mascarado)
    totvs-tickets-setup --remove   # apaga tudo
    totvs-tickets-setup --test     # tenta logar e imprime customerCode/orgs
"""

from __future__ import annotations

import getpass
import sys

import keyring
import keyring.errors

from .client import (
    KEYRING_SEED_KEY,
    KEYRING_SERVICE,
    KEYRING_TOKEN_KEY_KEY,
    KEYRING_USERNAME_KEY,
)


def show() -> int:
    user = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME_KEY)
    if not user:
        print("Nenhuma credencial cadastrada.")
        return 1
    pwd = keyring.get_password(KEYRING_SERVICE, user)
    seed = keyring.get_password(KEYRING_SERVICE, KEYRING_SEED_KEY)
    print(f"Username: {user}")
    print(f"Senha:    {'*' * len(pwd) if pwd else '(nao encontrada)'}")
    print(f"Seed TOTP: {'(cadastrado, ' + str(len(seed.replace(' ', ''))) + ' chars)' if seed else '(nao cadastrado)'}")
    return 0


def remove() -> int:
    user = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME_KEY)
    removed = False
    if user:
        try:
            keyring.delete_password(KEYRING_SERVICE, user)
            removed = True
        except keyring.errors.PasswordDeleteError:
            pass
    for key in (KEYRING_USERNAME_KEY, KEYRING_SEED_KEY, KEYRING_TOKEN_KEY_KEY):
        try:
            keyring.delete_password(KEYRING_SERVICE, key)
            removed = True
        except keyring.errors.PasswordDeleteError:
            pass
    print("Credenciais removidas." if removed else "Nada para remover.")
    return 0


def test_login() -> int:
    from .client import TotvsTicketsClient

    print("Tentando login (Fluig + MFA/TOTP + SAML)... isso pode levar alguns segundos.")
    try:
        client = TotvsTicketsClient()
        client.login()
    except Exception as e:
        print(f"FALHOU: {type(e).__name__}: {e}")
        print("Dica: rode com TOTVS_DEBUG=1 ou use `totvs-tickets-probe` pra inspecionar o fluxo.")
        return 1
    print("LOGIN OK.")
    print(f"  Usuario Zendesk (userId): {client.user_id}")
    print(f"  customerCode padrao:      {client.default_customer_code}")
    print("  Organizacoes:")
    for o in client.organizations:
        print(f"    - {o['external_id']}  {o['name']}  (id {o['id']})")
    return 0


def setup() -> int:
    current = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME_KEY) or ""
    prompt = f"Username Fluig (ex: nome.sobrenome) [{current}]: " if current else "Username Fluig (ex: nome.sobrenome): "
    user = input(prompt).strip() or current
    if not user:
        print("Username vazio, abortando.")
        return 2
    pwd = getpass.getpass("Senha: ")
    if not pwd:
        print("Senha vazia, abortando.")
        return 2
    print(
        "\nSeed TOTP (chave secreta do app autenticador). E a string base32 que\n"
        "aparece ao cadastrar o MFA ('nao consigo ler o QR / inserir manualmente').\n"
        "Pode colar com espacos/maiusculas ou minusculas."
    )
    seed = getpass.getpass("Seed TOTP: ").strip()
    if not seed:
        print("Seed vazio, abortando.")
        return 2
    # valida o seed cedo: precisa ser base32 valido
    try:
        from .client import _totp_now

        _totp_now(seed)
    except Exception:
        print("Seed TOTP invalido (nao e base32). Confira e tente de novo.")
        return 2

    if current and current != user:
        try:
            keyring.delete_password(KEYRING_SERVICE, current)
        except keyring.errors.PasswordDeleteError:
            pass

    keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME_KEY, user)
    keyring.set_password(KEYRING_SERVICE, user, pwd)
    keyring.set_password(KEYRING_SERVICE, KEYRING_SEED_KEY, seed)
    print(f"\nCredenciais salvas no keyring (servico '{KEYRING_SERVICE}').")
    print("Teste o login com: totvs-tickets-setup --test")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if "--show" in args:
        return show()
    if "--remove" in args:
        return remove()
    if "--test" in args:
        return test_login()
    return setup()


if __name__ == "__main__":
    sys.exit(main())
