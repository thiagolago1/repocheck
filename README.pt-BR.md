# repocheck

[English](README.md) | **Português (Brasil)**

> Analisa um repositório git em busca de conteúdo malicioso **antes** de você clonar ou instalar — nunca expondo sua máquina a código não confiável.

[![Licença: Apache 2.0](https://img.shields.io/badge/Licença-Apache%202.0-blue.svg)](LICENSE)

**🔗 [Landing page](https://thiagolago1.github.io/repocheck/)**

## O problema

Alguns repositórios maliciosos executam código no exato momento em que você clona ou instala: hooks de git, scripts de build (`postinstall`, `setup.py`), submódulos git maliciosos, ou filtros de `.gitattributes` forjados. Quando você percebe que algo está errado, o estrago já foi feito — na sua máquina.

O `repocheck` nunca clona nem executa nada do repositório-alvo no seu host. Tudo isso acontece dentro de uma máquina virtual descartável e isolada de rede, que é destruída depois de cada análise.

## Como funciona

```
┌──────────────────┐     ┌────────────────────┐     ┌───────────────────────────┐
│  Skill do Claude  │     │   CLI repocheck     │     │   VM descartável (Multipass)│
│  Code (opcional)  │────▶│   (Python, host)    │────▶│   - clone (rede ligada)     │
└──────────────────┘     └────────────────────┘     │   - scanners estáticos     │
                                    │                  │   - corte de rede          │
                                    ▼                  │   - tentativa de build     │
                          ┌────────────────────┐        │   - captura de telemetria  │
                          │  Pré-check de       │        └───────────────────────────┘
                          │  reputação via API  │                    │
                          │  (GitHub/GitLab/Bitbucket)    │                    ▼
                          └────────────────────┘        JSON de achados + veredito
```

1. **Pré-check de reputação** — consulta a API pública do GitHub/GitLab/Bitbucket por idade do repositório, estrelas/forks (quando disponível) e sinais de typosquatting. Puro metadado, nenhum código é tocado.
2. **VM descartável** — uma VM [Multipass](https://multipass.run/) novinha em folha é criada a cada análise e é **sempre destruída** depois, mesmo em caso de erro ou timeout.
3. **Scanners estáticos** (rodam dentro da VM, depois do clone, com a rede ainda ligada) — nunca executam nada, só leem arquivos:
   - Detecção de secrets (via [`detect-secrets`](https://github.com/Yelp/detect-secrets))
   - Padrões maliciosos (`curl | bash`, `eval` ofuscado, PowerShell codificado, etc.)
   - Checagens específicas de git (submódulos com transporte `ext::`, filtros customizados no `.gitattributes`, diretórios `.git` aninhados, nomes de arquivo com RTLO/homóglifos)
4. **Etapa dinâmica (duas fases)** — se um projeto `npm`/`pip` for detectado, a instalação é exercitada em duas fases separadas, pra que buscar dependências nunca seja confundido com malícia:
   - *Buscar (rede ligada, não vigiada):* as dependências são baixadas com o código de ciclo de vida desabilitado (`npm install --ignore-scripts` / `pip download`). Um gerenciador de pacotes acessando seu registry é comportamento esperado, não um sinal.
   - *Executar (rede cortada, vigiada):* com a rede então cortada via `iptables`, o código que uma instalação de fato roda — scripts de ciclo de vida (`postinstall`, etc.) e `setup.py` — é executado sob `strace`. Aqui, qualquer tentativa de conexão de saída é um sinal genuíno, já que um script de build não tem motivo legítimo pra "ligar pra casa" sem rede.
5. **Veredito** — um motor determinístico baseado em regras combina todos os sinais acima em `SAFE` / `SUSPICIOUS` / `MALICIOUS` (em inglês, para consistência internacional), sempre com motivos explícitos. Uma falha de scanner ou ausência de análise **nunca** vira "seguro" silenciosamente.
6. **Skill do Claude Code (opcional)** — pergunte em linguagem natural ("esse repositório é seguro pra instalar?") e o Claude roda o CLI, lê o veredito e os trechos já sinalizados, e complementa com o próprio julgamento — sem nunca tocar o repositório-alvo de novo (a VM já foi destruída quando o CLI retorna).

## Tecnologias usadas

| Camada | Tecnologia |
|---|---|
| CLI / orquestração | Python 3.11+, [Click](https://click.palletsprojects.com/) |
| Pré-check de reputação | APIs REST do GitHub/GitLab/Bitbucket via [`requests`](https://requests.readthedocs.io/) |
| Isolamento | [Multipass](https://multipass.run/) (VMs Ubuntu 24.04 descartáveis — funciona em macOS, Linux e Windows) |
| Scanner de secrets | [`detect-secrets`](https://github.com/Yelp/detect-secrets) |
| Telemetria de rede | `iptables` (corte) + `strace` (captura de tentativas de conexão) |
| Testes | `pytest`, `responses` (mock de HTTP), testes reais de ponta a ponta contra uma VM Multipass de verdade |
| Uso conversacional | Uma skill do [Claude Code](https://claude.com/claude-code) (`repocheck/.claude/skills/repo-safety-check/SKILL.md`) |

## Pré-requisitos

- Python 3.11+
- [Multipass](https://multipass.run/) — para a etapa de análise profunda (estática + dinâmica). Sem ele, o `repocheck` ainda roda o pré-check de reputação e reporta `SUSPICIOUS` com um aviso explícito; ele nunca finge que um repositório é seguro.

```bash
# macOS
brew install multipass

# Linux / Windows: veja https://multipass.run/install
```

## Instalação

```bash
git clone <url-deste-repositório>
cd repocheck
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Como usar

```bash
# Relatório legível
.venv/bin/repocheck https://github.com/<dono>/<repo>

# JSON pra máquina (usado pela skill do Claude Code)
.venv/bin/repocheck https://github.com/<dono>/<repo> --json
```

Exemplo de saída (sempre em inglês, para consistência entre usuários):

```
Checking repository reputation...
Launching disposable analysis VM (this can take a minute)...
Installing analysis tools inside the VM (git, npm, detect-secrets)...
Cloning the repository inside the isolated VM...
Running static and dynamic analysis (network is cut before any build step)...
Collecting results and destroying the VM...
VERDICT: SAFE

Reasons:
  - no relevant findings

Precheck:
  Platform: github
  Reachable: yes
  Age (days): 5636
  Stars: 3659
  Forks: 6128

Static analysis:
  Clone succeeded: yes
  Secrets found: 0
  Malicious patterns: 0
  Git findings: 0

Dynamic step:
  Attempted: no
```

### Usando de forma conversacional (Claude Code)

Dentro de uma sessão do [Claude Code](https://claude.com/claude-code) neste projeto, é só perguntar em linguagem natural:

> "Esse repositório é seguro pra clonar? https://github.com/\<dono\>/\<repo\>"

O Claude vai rodar o CLI, ler o veredito e os trechos já sinalizados na saída JSON, e complementar com o próprio julgamento sobre o veredito baseado em regras — veja `repocheck/.claude/skills/repo-safety-check/SKILL.md` pras instruções completas que ele segue.

## Rodando os testes

```bash
cd repocheck
PATH="$PWD/.venv/bin:$PATH" .venv/bin/pytest -v
```

Dois testes exigem uma VM Multipass real e são pulados automaticamente se ela não estiver instalada. Com o Multipass instalado, a suíte completa (128 testes) roda de ponta a ponta, incluindo uma execução real do pipeline de análise contra um repositório público.

## O que fica fora do escopo da v1

- Scanners além de secrets/padrões-maliciosos/checagens-de-git (ex: semgrep, YARA, OSV-Scanner).
- Ecossistemas de build além de npm/pip na etapa dinâmica.
- Cache/allowlist de repositórios já analisados.
- Backends de VM além do Multipass.

## Racional de design

Pra ver a discussão original de design (por que uma VM descartável, por que Multipass em vez de Lima, estratégia de testes, casos de borda), veja [`docs/design.pt-BR.md`](docs/design.pt-BR.md) ([English](docs/design.md)).

## Contribuindo

Pull requests são bem-vindos! Todas as contribuições passam por revisão antes do merge. Pra mudanças significativas, abra uma issue primeiro pra gente discutir a abordagem.

## Licença

[Apache License 2.0](LICENSE).
