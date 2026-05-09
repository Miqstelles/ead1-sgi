"""Gerencia keyrings GnuPG isolados por usuario."""

from __future__ import annotations

import os
from pathlib import Path

import gnupg


DEFAULT_KEYRINGS_DIR = Path("keyrings")


def get_gpg(user: str, base_dir: Path | str | None = None) -> gnupg.GPG:
    """Retorna instancia gnupg.GPG com keyring isolado para o usuario.

    GnuPG exige permissoes 700 no diretorio - garantimos isso aqui.
    """
    base = Path(base_dir) if base_dir else DEFAULT_KEYRINGS_DIR
    home = base / user
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    return gnupg.GPG(gnupghome=str(home))
