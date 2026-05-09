"""Cifragem com assinatura e decifragem com verificacao - fluxo PGP completo."""

from __future__ import annotations

import gnupg


def encrypt_and_sign(
    gpg_sender: gnupg.GPG,
    message: str,
    recipient_fp: str,
    signer_fp: str,
    passphrase: str,
) -> str:
    """Cifra e assina mensagem para um destinatario.

    Cobre os passos 1-4 do fluxo PGP do trabalho:
      1. Hash da mensagem assinado com chave privada do remetente
      2. Geracao de chave de sessao simetrica (feita pelo GnuPG internamente)
      3. Cifragem (mensagem + assinatura) com a chave de sessao
      4. Cifragem da chave de sessao com a chave publica do destinatario

    Retorna ciphertext em ASCII-armored (.asc).
    """
    crypt = gpg_sender.encrypt(
        message,
        recipients=[recipient_fp],
        sign=signer_fp,
        passphrase=passphrase,
        armor=True,
        always_trust=True,
    )
    if not crypt.ok:
        raise RuntimeError(f"Falha ao cifrar/assinar: {crypt.status} - {crypt.stderr}")
    return str(crypt)


def decrypt_and_verify(
    gpg_recipient: gnupg.GPG,
    ciphertext: str,
    passphrase: str,
) -> dict:
    """Decifra mensagem e verifica assinatura.

    Cobre os passos 6-8 do fluxo PGP do trabalho:
      6. Decifrar a chave de sessao com a chave privada do destinatario
      7. Decifrar a mensagem com a chave de sessao
      8. Verificar a assinatura com a chave publica do remetente

    Retorna dict com plaintext, validade da assinatura e identificacao do remetente.
    """
    result = gpg_recipient.decrypt(
        ciphertext,
        passphrase=passphrase,
        always_trust=True,
    )
    if not result.ok:
        raise RuntimeError(f"Falha ao decifrar: {result.status} - {result.stderr}")
    return {
        "plaintext": str(result),
        "valid": bool(result.valid),
        "fingerprint": result.fingerprint or "",
        "username": result.username or "",
        "trust_text": result.trust_text or "",
    }
