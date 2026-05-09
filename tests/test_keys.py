"""Testes de geracao, exportacao e importacao de chaves."""

from __future__ import annotations

import pytest

from pgp_chat.keys import (
    export_public_key,
    generate_keypair,
    import_public_key,
    list_keys,
)


def test_generate_keypair_returns_fingerprint(alice_gpg):
    fp = generate_keypair(
        alice_gpg, "Alice", "alice@example.com", "senha-teste"
    )
    assert fp
    assert len(fp) == 40  # SHA-1 fingerprint hex


def test_generated_key_appears_in_secret_keyring(alice_gpg):
    fp = generate_keypair(
        alice_gpg, "Alice", "alice@example.com", "senha-teste"
    )
    secret = list_keys(alice_gpg, secret=True)
    assert any(k["fingerprint"] == fp for k in secret)


def test_export_import_roundtrip(alice_gpg, bob_gpg):
    alice_fp = generate_keypair(
        alice_gpg, "Alice", "alice@example.com", "senha-alice"
    )
    armored = export_public_key(alice_gpg, alice_fp)
    assert armored.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")

    info = import_public_key(bob_gpg, armored)
    assert info["count"] == 1
    assert alice_fp in info["fingerprints"]

    bob_pub = list_keys(bob_gpg, secret=False)
    assert any(k["fingerprint"] == alice_fp for k in bob_pub)


def test_export_unknown_fingerprint_raises(alice_gpg):
    with pytest.raises(RuntimeError):
        export_public_key(alice_gpg, "0" * 40)
