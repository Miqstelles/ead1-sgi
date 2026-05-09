"""Testes do fluxo PGP completo - cifragem, decifragem, assinatura, tampering."""

from __future__ import annotations

import pytest

from pgp_chat.keys import generate_keypair
from pgp_chat.messages import decrypt_and_verify, encrypt_and_sign


def test_encrypt_decrypt_roundtrip_preserves_message(alice_bob_setup, alice_gpg, bob_gpg):
    """Golden path: Alice cifra+assina, Bob decifra+verifica."""
    fps = alice_bob_setup
    message = "Reuniao confidencial as 14h - sala 302"

    ciphertext = encrypt_and_sign(
        alice_gpg, message, fps["bob_fp"], fps["alice_fp"], fps["alice_pass"]
    )
    assert ciphertext.startswith("-----BEGIN PGP MESSAGE-----")

    result = decrypt_and_verify(bob_gpg, ciphertext, fps["bob_pass"])
    assert result["plaintext"] == message


def test_signature_is_verified_on_decrypt(alice_bob_setup, alice_gpg, bob_gpg):
    """Bob deve confirmar que a assinatura veio da Alice."""
    fps = alice_bob_setup
    ciphertext = encrypt_and_sign(
        alice_gpg, "msg", fps["bob_fp"], fps["alice_fp"], fps["alice_pass"]
    )
    result = decrypt_and_verify(bob_gpg, ciphertext, fps["bob_pass"])
    assert result["valid"] is True
    assert result["fingerprint"] == fps["alice_fp"]
    assert "alice@test.local" in result["username"].lower()


def test_decrypt_fails_for_wrong_recipient(alice_bob_setup, alice_gpg, charlie_gpg):
    """Charlie nao deve conseguir decifrar mensagem destinada a Bob."""
    fps = alice_bob_setup
    generate_keypair(
        charlie_gpg, "Charlie", "charlie@test.local", "charlie-pass"
    )

    ciphertext = encrypt_and_sign(
        alice_gpg, "segredo", fps["bob_fp"], fps["alice_fp"], fps["alice_pass"]
    )

    with pytest.raises(RuntimeError):
        decrypt_and_verify(charlie_gpg, ciphertext, "charlie-pass")


def test_tampered_ciphertext_is_rejected(alice_bob_setup, alice_gpg, bob_gpg):
    """Alterar o ciphertext deve invalidar a assinatura ou falhar a decifragem."""
    fps = alice_bob_setup
    ciphertext = encrypt_and_sign(
        alice_gpg, "intacta", fps["bob_fp"], fps["alice_fp"], fps["alice_pass"]
    )

    lines = ciphertext.splitlines()
    payload_idx = next(
        i for i, line in enumerate(lines)
        if line and not line.startswith("-----") and ":" not in line[:10]
    )
    payload_idx = max(payload_idx, 4)
    original = lines[payload_idx]
    tampered_char = "B" if original[0] != "B" else "C"
    lines[payload_idx] = tampered_char + original[1:]
    tampered = "\n".join(lines)

    try:
        result = decrypt_and_verify(bob_gpg, tampered, fps["bob_pass"])
        assert result["valid"] is False
    except RuntimeError:
        pass


def test_wrong_passphrase_fails(alice_bob_setup, alice_gpg, bob_gpg):
    """Bob com passphrase errada nao decifra."""
    fps = alice_bob_setup
    ciphertext = encrypt_and_sign(
        alice_gpg, "msg", fps["bob_fp"], fps["alice_fp"], fps["alice_pass"]
    )
    with pytest.raises(RuntimeError):
        decrypt_and_verify(bob_gpg, ciphertext, "passphrase-errada")
