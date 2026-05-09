"""Geracao, exportacao, importacao e listagem de chaves PGP."""

from __future__ import annotations

import gnupg


def generate_keypair(
    gpg: gnupg.GPG,
    name: str,
    email: str,
    passphrase: str,
    key_length: int = 2048,
) -> str:
    """Gera par de chaves RSA e retorna o fingerprint."""
    input_data = gpg.gen_key_input(
        name_real=name,
        name_email=email,
        passphrase=passphrase,
        key_type="RSA",
        key_length=key_length,
        expire_date=0,
    )
    key = gpg.gen_key(input_data)
    if not key.fingerprint:
        raise RuntimeError(f"Falha ao gerar chave para {name} <{email}>: {key.stderr}")
    return key.fingerprint


def export_public_key(gpg: gnupg.GPG, fingerprint: str) -> str:
    """Exporta chave publica em formato ASCII-armored."""
    armored = gpg.export_keys(fingerprint, armor=True)
    if not armored:
        raise RuntimeError(f"Chave nao encontrada: {fingerprint}")
    return armored


def import_public_key(gpg: gnupg.GPG, key_data: str) -> dict:
    """Importa chave publica e retorna info do resultado."""
    result = gpg.import_keys(key_data)
    if result.count == 0:
        raise RuntimeError(f"Falha ao importar chave: {result.results}")
    return {
        "count": result.count,
        "fingerprints": result.fingerprints,
    }


def list_keys(gpg: gnupg.GPG, secret: bool = False) -> list[dict]:
    """Lista chaves no keyring."""
    keys = gpg.list_keys(secret=secret)
    return [
        {
            "fingerprint": k["fingerprint"],
            "uids": k["uids"],
            "length": k["length"],
            "type": k["type"],
        }
        for k in keys
    ]
