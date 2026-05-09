---
title: "Trabalho — Caso de Uso PGP em Aplicativo de Mensagens"
subtitle: "Segurança de Sistemas de Informação"
author: "Miqueias Telles — RA HT3038475"
date: "09 de maio de 2026"
lang: pt-BR
geometry: margin=2.5cm
fontsize: 11pt
mainfont: "Helvetica"
monofont: "Menlo"
toc: true
toc-depth: 2
numbersections: true
---

# Identificação

| Campo | Valor |
|---|---|
| Disciplina | Segurança de Sistemas de Informação |
| Aluno | Miqueias Telles |
| Registro Acadêmico | HT3038475 |
| Data de entrega | 09/05/2026 |
| Formato do grupo | Entrega individual |

# Resumo individual — Kurose, Capítulo 8 ("Segurança em Redes")

O capítulo 8 de KUROSE & ROSS apresenta os fundamentos da segurança de redes
de computadores, organizando o tema em torno de quatro propriedades desejáveis
em qualquer sistema seguro: **confidencialidade**, **integridade**,
**autenticidade** e **não-repúdio**. A confidencialidade garante que somente
o destinatário leia o conteúdo trocado; a integridade assegura que a mensagem
não foi alterada em trânsito; a autenticidade comprova a identidade do
remetente; e o não-repúdio impede que o remetente negue, posteriormente, a
autoria da mensagem.

## Criptografia simétrica

O autor introduz a criptografia simétrica como o esquema mais antigo, em que
remetente e destinatário compartilham uma mesma chave secreta `K`. Algoritmos
clássicos abordados são o DES (hoje obsoleto pelo tamanho de chave), o 3DES
e, principalmente, o **AES** (Advanced Encryption Standard), padrão atual com
blocos de 128 bits e chaves de 128, 192 ou 256 bits. Cifras de bloco utilizam
modos de operação como CBC e CTR para encadear blocos com vetor de
inicialização. O ponto fraco da criptografia simétrica é o **problema de
distribuição da chave**: como combinar `K` com a outra ponta sem que um
adversário a intercepte? Esse problema motiva os esquemas assimétricos.

## Criptografia assimétrica (chave pública)

A criptografia assimétrica resolve a distribuição de chaves usando um par
matemático: cada usuário possui uma **chave pública** (publicada livremente)
e uma **chave privada** (mantida em segredo). O algoritmo paradigmático é o
**RSA**, baseado na dificuldade de fatorar produtos de números primos
grandes. Em RSA, mensagens cifradas com a chave pública só podem ser
decifradas com a chave privada correspondente, e vice-versa. A operação é,
porém, computacionalmente cara — por isso, na prática, usa-se RSA apenas
para transportar uma **chave de sessão simétrica** (geralmente AES), que é
quem cifra o volume real de dados. Esse é o cerne dos esquemas híbridos
descritos adiante.

## Funções hash, MAC e assinatura digital

Funções hash criptográficas (MD5 — quebrado, SHA-1 — depreciado, SHA-256 —
recomendado) produzem um resumo de tamanho fixo de uma entrada arbitrária,
com as propriedades de resistência à pré-imagem e à colisão. Aplicar hash
ao conteúdo, porém, não basta: um adversário pode alterar a mensagem **e**
o hash. Daí surgem dois mecanismos complementares:

- **MAC (Message Authentication Code)** — combina hash com chave simétrica
  compartilhada, garantindo integridade + autenticidade entre as duas partes
  que possuem a chave.
- **Assinatura digital** — é o hash da mensagem **cifrado com a chave privada
  do remetente**. Qualquer pessoa que possua a chave pública correspondente
  pode verificar a assinatura, obtendo simultaneamente integridade,
  autenticidade e não-repúdio (já que apenas o dono da chave privada poderia
  produzi-la).

## Distribuição de chaves e certificados

Ao trocar chaves pela rede surge o ataque do "homem-no-meio". Kurose descreve
duas soluções clássicas:

1. **KDC (Key Distribution Center)** — autoridade simétrica central que
   compartilha uma chave com cada usuário e intermedia o estabelecimento de
   chaves de sessão. Modelo do Kerberos.
2. **CA (Certificate Authority)** — entidade que emite **certificados X.509**
   amarrando uma chave pública a uma identidade verificada. É o modelo da web
   (HTTPS/TLS) e o que sustenta a confiança em PKI hierárquicas.

PGP, alvo deste trabalho, adota um modelo alternativo conhecido como **rede
de confiança** (web of trust), em que a confiança é construída socialmente
por assinaturas mútuas — sem CA central.

## Email seguro / PGP — o caso central

O capítulo dedica seção específica ao **PGP (Pretty Good Privacy)**, criado
por Phil Zimmermann em 1991, e que se tornou padrão do mundo open-source via
**GnuPG (GPG)** sob o RFC 4880 (OpenPGP). PGP combina, em um único protocolo,
todas as primitivas anteriores para entregar as quatro propriedades da
segurança em uma única mensagem:

1. O remetente calcula o **hash** da mensagem e o **assina** com sua chave
   privada (RSA).
2. O remetente gera uma **chave de sessão simétrica** aleatória (AES).
3. **Cifra** mensagem + assinatura com essa chave de sessão.
4. **Cifra a chave de sessão** com a chave pública do destinatário (RSA).
5. Envia o pacote cifrado (mensagem cifrada + chave de sessão cifrada).

O destinatário inverte os passos: decifra a chave de sessão com sua chave
privada, decifra a mensagem com a chave de sessão e verifica a assinatura
com a chave pública do remetente. Confidencialidade vem da etapa simétrica;
distribuição da chave de sessão vem do envelope assimétrico; integridade,
autenticidade e não-repúdio vêm da assinatura digital.

A escolha desse esquema híbrido (assimétrico para chave + simétrico para
conteúdo) é justificada por **desempenho** (RSA é ~1000× mais lento que AES
para volumes grandes) sem abrir mão das garantias da chave pública.

# Proposta de caso de uso — PGP em aplicativo de mensagens

## Cenário

Alice e Bob são dois usuários de um aplicativo de mensagens corporativo.
Alice precisa enviar a Bob a frase **"Reunião confidencial às 14h — sala
302"**. O canal de transporte (servidor de mensagens, rede Wi-Fi) é
considerado **não confiável** — pode haver interceptação, alteração ou
repúdio do conteúdo. As exigências da política de segurança são as quatro
propriedades clássicas:

| Propriedade | Exigência |
|---|---|
| Confidencialidade | Apenas Bob pode ler |
| Integridade | Bob detecta qualquer alteração |
| Autenticidade | Bob confirma que veio da Alice |
| Não-repúdio | Alice não pode negar a autoria |

A solução adotada é o esquema híbrido PGP, conforme o capítulo 8 do Kurose,
implementado sobre o GnuPG (RFC 4880).

## Fluxo PGP completo

```
ALICE (remetente)                              BOB (destinatário)
────────────────                               ──────────────────
M  = mensagem em claro                         (recebe C, K_enc)
H  = SHA-256(M)
S  = RSA_priv_alice(H)        ─── assinar
K  = AES-256 random            ─── chave sessão
C  = AES_K(M ‖ S)              ─── cifrar
K_enc = RSA_pub_bob(K)         ─── envelope
                                               K   = RSA_priv_bob(K_enc)
                                               M‖S = AES_K(C)
                                               H'  = SHA-256(M)
                                  ←── envia    valida: H' = RSA_pub_alice(S) ?
```

Cada etapa atende a um requisito da tabela acima:

- A **assinatura S** garante integridade, autenticidade e não-repúdio.
- A **cifragem com K** garante confidencialidade da mensagem em trânsito.
- O **envelope K_enc** resolve o problema de distribuição da chave de sessão.

## Mapeamento para a CLI implementada

| Passo do fluxo PGP | Comando da CLI |
|---|---|
| Geração do par RSA da Alice e do Bob | `pgp-chat gen-key --user alice ...`, `pgp-chat gen-key --user bob ...` |
| Distribuição das chaves públicas (Alice ↔ Bob) | `pgp-chat export-key`, `pgp-chat import-key` |
| Passos 1–4 (assinar + cifrar + envelopar) | `pgp-chat send --from alice --to bob ...` |
| Passos 6–8 (decifrar + verificar) | `pgp-chat receive --user bob ...` |

Saída real obtida na execução de demonstração:

```
=== Mensagem recebida ===
Conteudo: 'Reuniao confidencial as 14h - sala 302'
Assinatura valida: SIM
Remetente (fingerprint): 3DA153FB74F8C34E65E3307AED718066F691D9A0
Remetente (uid): Alice Silva <alice@ead.local>
```

## Cobertura por testes automatizados

Cinco cenários do fluxo PGP são exercitados na suíte `pytest` (9 testes
totais — todos verdes na máquina de desenvolvimento):

1. **Round-trip íntegro** — Alice cifra, Bob decifra, mensagem original é
   recuperada.
2. **Verificação de assinatura** — campo `valid=True` e fingerprint do
   remetente igual ao da Alice.
3. **Destinatário errado** — Charlie (terceiro keyring) tenta decifrar e
   recebe erro.
4. **Tampering** — alterar 1 byte do ciphertext invalida a assinatura ou
   falha a decifragem.
5. **Passphrase errada** — Bob com senha incorreta não consegue acessar a
   chave privada.

# Implementação

| Item | Detalhe |
|---|---|
| Linguagem | Python 3.9+ |
| Biblioteca de criptografia | `python-gnupg` 0.5+ (wrapper sobre GnuPG/OpenPGP) |
| Backend criptográfico | GnuPG 2.5 (RFC 4880) |
| Framework de testes | pytest 8 |
| Conversão de documento | pandoc + xelatex |
| Repositório | `https://github.com/<usuario>/pgp-chat-sgi` *(placeholder — atualizar após `gh repo create`)* |

A escolha de `python-gnupg` em vez de `cryptography` ou `PyCryptodome` se dá
porque o GnuPG implementa o **OpenPGP real** (formato `.asc`,
inter-operável com Thunderbird+Enigmail, GPGTools, ProtonMail), em
conformidade com o caso de uso descrito por Kurose. Bibliotecas como
`cryptography` permitiriam montar manualmente o esquema RSA+AES+SHA, mas
sem produzir mensagens OpenPGP genuínas.

## Comandos disponíveis

```
pgp-chat gen-key    --user <u> --name <n> --email <e> --passphrase <p>
pgp-chat export-key --user <u> --out <arq>
pgp-chat import-key --user <u> --in  <arq>
pgp-chat list-keys  --user <u>
pgp-chat send       --from <u> --to <id> --message <m> --out <arq> --passphrase <p>
pgp-chat receive    --user <u> --in <arq> --passphrase <p>
```

# Divisão do trabalho

Trabalho entregue de forma **individual**. Todas as áreas exigidas pelo
enunciado foram realizadas pelo aluno abaixo:

| Área | Responsável |
|---|---|
| Levantamento de requisitos | Miqueias Telles — HT3038475 |
| Resumo do Kurose | Miqueias Telles — HT3038475 |
| Proposta de caso de uso PGP | Miqueias Telles — HT3038475 |
| Implementação (CLI Python) | Miqueias Telles — HT3038475 |
| Testes automatizados | Miqueias Telles — HT3038475 |
| Documentação (este texto + README) | Miqueias Telles — HT3038475 |

# Referências

1. KUROSE, J. F.; ROSS, K. W. **Redes de Computadores e a Internet — Uma
   Abordagem Top-Down**. 8ª edição. Pearson, 2021. Capítulo 8 — Segurança
   em Redes.
2. ZIMMERMANN, P. **PGP User's Guide**. MIT, 1995.
3. CALLAS, J.; DONNERHACKE, L.; FINNEY, H. et al. **RFC 4880 — OpenPGP
   Message Format**. IETF, 2007.
4. python-gnupg — documentação oficial: <https://gnupg.readthedocs.io>
5. **Como criptografar em Python**: <https://pt.ittrip.xyz/python/python-cryptography-basics>
6. DevMedia — Algoritmos de criptografia em Python: <https://www.devmedia.com.br/>
