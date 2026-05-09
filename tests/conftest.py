"""Fixtures compartilhadas - keyrings temporarios isolados por teste."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from pgp_chat.keys import (
    export_public_key,
    generate_keypair,
    import_public_key,
)
from pgp_chat.storage import get_gpg


PASSPHRASE_ALICE = "alice-test-pass"
PASSPHRASE_BOB = "bob-test-pass"
PASSPHRASE_CHARLIE = "charlie-test-pass"


@pytest.fixture
def tmp_keyrings() -> Path:
    """Diretorio temporario curto - gpg-agent socket tem limite de ~104 chars no macOS.

    Usar pytest tmp_path falha porque o caminho excede o limite do Unix socket.
    """
    base = Path(tempfile.mkdtemp(prefix="pgpkr-", dir="/tmp"))
    yield base
    shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def alice_gpg(tmp_keyrings: Path):
    return get_gpg("alice", tmp_keyrings)


@pytest.fixture
def bob_gpg(tmp_keyrings: Path):
    return get_gpg("bob", tmp_keyrings)


@pytest.fixture
def charlie_gpg(tmp_keyrings: Path):
    return get_gpg("charlie", tmp_keyrings)


@pytest.fixture
def alice_bob_setup(alice_gpg, bob_gpg) -> dict:
    """Gera chaves para Alice e Bob, troca chaves publicas. Retorna fingerprints."""
    alice_fp = generate_keypair(
        alice_gpg, "Alice Test", "alice@test.local", PASSPHRASE_ALICE
    )
    bob_fp = generate_keypair(
        bob_gpg, "Bob Test", "bob@test.local", PASSPHRASE_BOB
    )

    alice_pub = export_public_key(alice_gpg, alice_fp)
    bob_pub = export_public_key(bob_gpg, bob_fp)

    import_public_key(bob_gpg, alice_pub)
    import_public_key(alice_gpg, bob_pub)

    return {
        "alice_fp": alice_fp,
        "bob_fp": bob_fp,
        "alice_pass": PASSPHRASE_ALICE,
        "bob_pass": PASSPHRASE_BOB,
    }
