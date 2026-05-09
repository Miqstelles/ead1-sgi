# PGP Chat — Demo SGI

Demonstração de **proteção PGP em aplicativo de mensagens** para o trabalho
da disciplina **Segurança de Sistemas de Informação**. Uma CLI Python
simula a troca de mensagens cifradas e assinadas entre dois usuários
(Alice ↔ Bob) usando OpenPGP via GnuPG.

> Documento individual completo (com resumo do Kurose) em
> [`docs/trabalho-pgp.md`](docs/trabalho-pgp.md) — versão final em PDF em
> [`docs/trabalho-pgp.pdf`](docs/trabalho-pgp.pdf).

## Requisitos

### Funcionais

1. Gerar par de chaves RSA (mínimo 2048 bits) por usuário, com keyring
   isolado por diretório.
2. Exportar chave pública em formato ASCII-armored (`.asc`).
3. Importar chave pública de outro usuário no keyring local.
4. Listar chaves públicas e secretas presentes no keyring.
5. Cifrar e assinar uma mensagem em uma única operação (esquema híbrido
   PGP — RSA para envelope, AES-256 para conteúdo, assinatura RSA+SHA-256
   sobre o hash).
6. Decifrar e verificar a assinatura, retornando o status da assinatura,
   o fingerprint e o UID do remetente.
7. Falhar de forma segura quando: passphrase errada, destinatário diferente,
   ou ciphertext adulterado.

### Não funcionais

- Implementação em **Python 3.9+** com **python-gnupg** sobre **GnuPG ≥ 2.4**.
- Suíte de testes automatizados (`pytest`) com isolamento total por keyring
  temporário.
- Mensagens cifradas em formato OpenPGP padrão (RFC 4880), interoperáveis
  com clientes externos (Thunderbird, GPGTools etc.).
- Sem persistência de chaves entre execuções dos testes.

## Tecnologias

| Componente | Versão | Função |
|---|---|---|
| Python | 3.9+ | Linguagem |
| python-gnupg | 0.5+ | Wrapper Python para GnuPG |
| GnuPG | 2.4+ | Backend OpenPGP |
| pytest | 8.x | Framework de testes |
| pandoc + xelatex | — | Geração do PDF |

## Instalação

```bash
# Dependências de sistema (macOS via Homebrew)
brew install gnupg pandoc

# Dependências Python
python3 -m pip install --user -r requirements.txt
```

Em Linux: `sudo apt install gnupg pandoc texlive-xetex`.

## Uso — Demonstração Alice → Bob

```bash
# 1. Geração de chaves
PYTHONPATH=src python3 -m pgp_chat.cli gen-key \
    --user alice --name "Alice Silva" --email alice@ead.local \
    --passphrase senha-alice

PYTHONPATH=src python3 -m pgp_chat.cli gen-key \
    --user bob --name "Bob Souza" --email bob@ead.local \
    --passphrase senha-bob

# 2. Distribuição das chaves públicas
PYTHONPATH=src python3 -m pgp_chat.cli export-key --user alice --out alice.pub
PYTHONPATH=src python3 -m pgp_chat.cli export-key --user bob   --out bob.pub
PYTHONPATH=src python3 -m pgp_chat.cli import-key --user bob   --in alice.pub
PYTHONPATH=src python3 -m pgp_chat.cli import-key --user alice --in bob.pub

# 3. Alice cifra+assina e envia
PYTHONPATH=src python3 -m pgp_chat.cli send \
    --from alice --to bob@ead.local \
    --message "Reuniao confidencial as 14h" \
    --out msg.asc --passphrase senha-alice

# 4. Bob decifra+verifica
PYTHONPATH=src python3 -m pgp_chat.cli receive \
    --user bob --in msg.asc --passphrase senha-bob
```

Saída esperada do passo 4:

```
=== Mensagem recebida ===
Conteudo: 'Reuniao confidencial as 14h'
Assinatura valida: SIM
Remetente (fingerprint): 3DA153FB74F8C34E65E3307AED718066F691D9A0
Remetente (uid): Alice Silva <alice@ead.local>
```

## Testes

```bash
python3 -m pytest tests/ -v
```

Resultado atual: **9/9 testes verdes** cobrindo geração de chaves, troca,
round-trip, verificação de assinatura, destinatário errado, tampering e
passphrase errada.

## Estrutura do projeto

```
ead1-sgi/
├── docs/
│   ├── trabalho-pgp.md       # Documento individual (resumo Kurose + proposta)
│   └── trabalho-pgp.pdf      # Versao final para entrega
├── src/pgp_chat/
│   ├── cli.py                # argparse + subcomandos
│   ├── keys.py               # geracao, export, import, listagem
│   ├── messages.py           # encrypt+sign / decrypt+verify
│   └── storage.py            # keyrings isolados por usuario
└── tests/
    ├── conftest.py           # fixtures (keyring temporario curto)
    ├── test_keys.py          # 4 testes
    └── test_messages.py      # 5 testes
```

## Divisão do trabalho

Entrega **individual**. Todas as etapas exigidas pelo enunciado foram
realizadas pelo aluno abaixo:

| Área | Responsável | Arquivos principais |
|---|---|---|
| Requisitos | Miqueias Telles — HT3038475 | `README.md` (esta seção), `docs/trabalho-pgp.md` |
| Implementação | Miqueias Telles — HT3038475 | `src/pgp_chat/` |
| Testes | Miqueias Telles — HT3038475 | `tests/` |
| Documentação | Miqueias Telles — HT3038475 | `docs/trabalho-pgp.md`, `README.md` |

## Referências

- KUROSE, J. F.; ROSS, K. W. *Redes de Computadores e a Internet — Uma
  Abordagem Top-Down*. 8ª ed. Cap. 8 (Segurança em Redes).
- RFC 4880 — OpenPGP Message Format.
- python-gnupg: <https://gnupg.readthedocs.io>
- Como criptografar em Python: <https://pt.ittrip.xyz/python/python-cryptography-basics>
