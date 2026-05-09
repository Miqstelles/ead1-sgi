"""CLI do pgp_chat - simula troca de mensagens cifradas entre usuarios."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import keys as keys_mod
from . import messages as msg_mod
from .storage import get_gpg


def cmd_gen_key(args: argparse.Namespace) -> int:
    print(f"[*] Gerando par de chaves RSA-{args.key_length} para {args.user}...")
    gpg = get_gpg(args.user, args.keyrings_dir)
    fp = keys_mod.generate_keypair(
        gpg, args.name, args.email, args.passphrase, args.key_length
    )
    print(f"[ok] Chave gerada. Fingerprint: {fp}")
    return 0


def cmd_export_key(args: argparse.Namespace) -> int:
    gpg = get_gpg(args.user, args.keyrings_dir)
    all_keys = keys_mod.list_keys(gpg, secret=True)
    if not all_keys:
        print(f"[erro] Nenhuma chave secreta encontrada para {args.user}", file=sys.stderr)
        return 1
    fp = args.fingerprint or all_keys[0]["fingerprint"]
    armored = keys_mod.export_public_key(gpg, fp)
    Path(args.out).write_text(armored)
    print(f"[ok] Chave publica de {args.user} ({fp}) exportada para {args.out}")
    return 0


def cmd_import_key(args: argparse.Namespace) -> int:
    gpg = get_gpg(args.user, args.keyrings_dir)
    key_data = Path(getattr(args, "in")).read_text()
    info = keys_mod.import_public_key(gpg, key_data)
    print(f"[ok] {info['count']} chave(s) importada(s) no keyring de {args.user}")
    for fp in info["fingerprints"]:
        print(f"     - {fp}")
    return 0


def cmd_list_keys(args: argparse.Namespace) -> int:
    gpg = get_gpg(args.user, args.keyrings_dir)
    pub = keys_mod.list_keys(gpg, secret=False)
    sec = keys_mod.list_keys(gpg, secret=True)
    print(f"=== Keyring de {args.user} ===")
    print(f"Chaves publicas ({len(pub)}):")
    for k in pub:
        print(f"  {k['fingerprint']}  {', '.join(k['uids'])}")
    print(f"Chaves secretas ({len(sec)}):")
    for k in sec:
        print(f"  {k['fingerprint']}  {', '.join(k['uids'])}")
    return 0


def _resolve_fingerprint(gpg, identifier: str) -> str:
    """Resolve um identificador (fingerprint, email ou nome) para um fingerprint."""
    keys = gpg.list_keys()
    for k in keys:
        if k["fingerprint"] == identifier or identifier.upper() == k["keyid"]:
            return k["fingerprint"]
        for uid in k["uids"]:
            if identifier.lower() in uid.lower():
                return k["fingerprint"]
    raise SystemExit(f"[erro] Chave nao encontrada para identificador: {identifier}")


def cmd_send(args: argparse.Namespace) -> int:
    print(f"[1/4] Carregando keyring de {getattr(args, 'from')}...")
    gpg = get_gpg(getattr(args, "from"), args.keyrings_dir)

    print(f"[2/4] Resolvendo destinatario {args.to}...")
    recipient_fp = _resolve_fingerprint(gpg, args.to)

    print(f"[3/4] Resolvendo signatario {getattr(args, 'from')}...")
    sec = keys_mod.list_keys(gpg, secret=True)
    if not sec:
        print(f"[erro] {getattr(args, 'from')} nao possui chave secreta", file=sys.stderr)
        return 1
    signer_fp = sec[0]["fingerprint"]

    print(f"[4/4] Assinando + cifrando mensagem (passos 1-4 do fluxo PGP)...")
    ciphertext = msg_mod.encrypt_and_sign(
        gpg, args.message, recipient_fp, signer_fp, args.passphrase
    )
    Path(args.out).write_text(ciphertext)
    print(f"[ok] Mensagem cifrada e assinada salva em {args.out}")
    print(f"     Remetente: {signer_fp}")
    print(f"     Destinatario: {recipient_fp}")
    return 0


def cmd_receive(args: argparse.Namespace) -> int:
    print(f"[1/3] Carregando keyring de {args.user}...")
    gpg = get_gpg(args.user, args.keyrings_dir)

    print(f"[2/3] Lendo ciphertext de {getattr(args, 'in')}...")
    ciphertext = Path(getattr(args, "in")).read_text()

    print(f"[3/3] Decifrando + verificando assinatura (passos 6-8 do fluxo PGP)...")
    result = msg_mod.decrypt_and_verify(gpg, ciphertext, args.passphrase)

    print()
    print(f"=== Mensagem recebida ===")
    print(f"Conteudo: {result['plaintext']!r}")
    print(f"Assinatura valida: {'SIM' if result['valid'] else 'NAO'}")
    print(f"Remetente (fingerprint): {result['fingerprint']}")
    print(f"Remetente (uid): {result['username']}")
    print(f"Confianca: {result['trust_text']}")
    return 0 if result["valid"] else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pgp-chat",
        description="Demo PGP em app de mensagens (Trabalho SGI)",
    )
    parser.add_argument(
        "--keyrings-dir",
        default="keyrings",
        help="Diretorio base dos keyrings (default: ./keyrings)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("gen-key", help="Gera par de chaves RSA")
    p_gen.add_argument("--user", required=True)
    p_gen.add_argument("--name", required=True)
    p_gen.add_argument("--email", required=True)
    p_gen.add_argument("--passphrase", required=True)
    p_gen.add_argument("--key-length", type=int, default=2048)
    p_gen.set_defaults(func=cmd_gen_key)

    p_exp = sub.add_parser("export-key", help="Exporta chave publica (ASCII-armored)")
    p_exp.add_argument("--user", required=True)
    p_exp.add_argument("--out", required=True)
    p_exp.add_argument("--fingerprint", default=None)
    p_exp.set_defaults(func=cmd_export_key)

    p_imp = sub.add_parser("import-key", help="Importa chave publica de outro usuario")
    p_imp.add_argument("--user", required=True)
    p_imp.add_argument("--in", required=True, dest="in")
    p_imp.set_defaults(func=cmd_import_key)

    p_list = sub.add_parser("list-keys", help="Lista chaves do keyring")
    p_list.add_argument("--user", required=True)
    p_list.set_defaults(func=cmd_list_keys)

    p_send = sub.add_parser("send", help="Cifra+assina mensagem (Alice -> Bob)")
    p_send.add_argument("--from", required=True, dest="from")
    p_send.add_argument("--to", required=True, help="fingerprint, email ou nome do destinatario")
    p_send.add_argument("--message", required=True)
    p_send.add_argument("--out", required=True)
    p_send.add_argument("--passphrase", required=True)
    p_send.set_defaults(func=cmd_send)

    p_recv = sub.add_parser("receive", help="Decifra+verifica mensagem")
    p_recv.add_argument("--user", required=True)
    p_recv.add_argument("--in", required=True, dest="in")
    p_recv.add_argument("--passphrase", required=True)
    p_recv.set_defaults(func=cmd_receive)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
