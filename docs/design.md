# Repo Safety Check — Design

## Problema

Antes de clonar e instalar um repositório de código de origem desconhecida (GitHub, GitLab, ou qualquer host git), queremos verificar se ele contém código malicioso. Alguns repositórios maliciosos executam código já no momento do clone/instalação (hooks de git, scripts de build tipo `postinstall`/`setup.py`, submódulos ou filtros de `.gitattributes` maliciosos), então a verificação em si precisa acontecer num ambiente totalmente isolado da máquina do usuário — nunca clonando ou executando nada do repositório-alvo diretamente no host.

## Objetivo da v1

Dado uma URL de repositório, produzir um veredito (SAFE / SUSPICIOUS / MALICIOUS) com relatório detalhado, sem nunca expor a máquina do usuário ao conteúdo não confiável do repositório.

## Arquitetura

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────────┐
│  Claude Code     │     │   repocheck CLI   │     │   VM efêmera (Multipass)│
│  skill           │────▶│   (Python, host)  │────▶│   - clone (rede on)     │
│  /repo-check url │     │   orquestrador    │     │   - corta rede          │
└─────────────────┘     └──────────────────┘     │   - scanners estáticos │
        ▲                        │                 │   - passo dinâmico     │
        │                        │                 │     genérico (sandbox) │
        │                        ▼                 │   - captura telemetria │
        │              ┌──────────────────┐        └─────────────────────────┘
        │              │  Pré-check via   │                    │
        │              │  API da          │                    ▼
        │              │  plataforma      │        JSON com achados brutos
        │              │  (GitHub/GitLab) │        (scanners + telemetria)
        │              └──────────────────┘                    │
        │                                                       ▼
        │                                          Claude lê os achados +
        └──────────────────────────────────────────  arquivos sinalizados e
                                                       julga intenção (LLM review)
                                                                 │
                                                                 ▼
                                                   Veredito final + relatório
```

## Decisões principais

- **Interface:** CLI standalone em Python (`repocheck <url>`) + skill do Claude Code que invoca o mesmo núcleo, permitindo uso tanto direto no terminal/CI quanto conversacional.
- **Tipo de análise:** estática (nunca executa nada do repositório) **e** dinâmica sandboxed (executa clone/build/install de fato, mas dentro de uma VM descartável).
- **Isolamento:** VM local descartável via **Multipass** (não Lima) — Multipass é genuinamente multiplataforma (Hyper-V no Windows, QEMU/KVM no Linux, Virtualization.framework no macOS) usando a mesma interface de CLI, o que garante suporte real a Windows/Linux/macOS já na v1.
- **Motor de detecção:** combinação de scanners de segurança estabelecidos (detecção de secrets, scanner de dependências vulneráveis agnóstico de linguagem — ex. OSV-Scanner —, regras de padrões maliciosos, checagens específicas de git) **com** revisão por LLM. A revisão por LLM é feita pela própria sessão do Claude Code lendo o JSON de achados e os trechos sinalizados — não uma chamada de API separada dentro do Python. Quando o CLI roda fora do Claude Code (`--json-only`), essa etapa fica indisponível e o relatório deixa isso explícito.
- **Escopo de ecossistema:** genérico — o foco é o repositório git como um todo (hooks, submódulos, `.gitattributes`/filtros, Makefiles, scripts de shell), não um gerenciador de pacotes específico. Scanners de dependência agnósticos de linguagem são usados quando manifestos conhecidos existem.
- **Política de rede na VM:** rede permitida só durante o clone inicial; depois é cortada por regra de firewall interna antes de qualquer passo de build/instalação. Tentativas de rede após o corte são logadas como sinal forte de comportamento malicioso.
- **Relatório:** veredito no topo (SAFE/SUSPICIOUS/MALICIOUS) + seções detalhadas com achados dos scanners, telemetria da VM (processos, acessos a arquivo fora do repo, tentativas de rede bloqueadas) e a análise da LLM sobre os trechos sinalizados.

## Componentes

1. **`repocheck` (CLI Python, host)** — orquestrador. Comandos: `repocheck <url>` (pipeline completo) e `repocheck <url> --json-only` (sem etapa de LLM, para CI ou quando chamado pela skill).
2. **Pré-check via API (host)** — identifica a plataforma pela URL e consulta a API pública (idade do repo, estrelas/forks, verificação do autor/org, sinais de typosquatting no nome). Puramente metadado, nunca toca no código. Plataformas desconhecidas pulam essa etapa sem erro.
3. **Script de análise (dentro da VM Multipass)** — copiado para dentro da VM antes dela subir (nunca baixado do alvo). Executa: clone → corte de rede → scanners estáticos → etapa dinâmica genérica (tenta os passos de build/install que o repo declarar) → captura de telemetria → escreve JSON estruturado.
4. **Ciclo de vida da VM (host)** — cria uma instância nova a cada análise (nunca reaproveitada), copia o JSON de saída, e **sempre** destrói a VM ao final — inclusive em timeout/erro/crash.
5. **Revisão por LLM (sessão Claude Code)** — lê o JSON + trechos sinalizados, decide o que investigar mais a fundo, produz julgamento de intenção.
6. **Skill do Claude Code** — expõe isso como comando em linguagem natural, chama o `repocheck --json-only`, e apresenta o veredito conversacionalmente.

## Fluxo de dados

1. Input: URL do repositório (direto ou via linguagem natural na skill).
2. Pré-check via API (host, segundos) — sinaliza reputação antes de gastar tempo com VM, mas não pula a análise completa por padrão.
3. Provisionamento de uma VM Multipass nova, a partir de imagem base fixa.
4. Clone do repositório (rede ligada) seguido de corte de rede dentro da VM.
5. Scanners estáticos rodam sobre os arquivos sem executar nada.
6. Etapa dinâmica: passos de build/install declarados são tentados, com toda execução de processo, acesso a arquivo fora do repo e tentativa de rede bloqueada sendo capturada.
7. Único artefato que sai da VM: o JSON de achados + telemetria (nunca o código-fonte do repositório).
8. VM é destruída — sempre, mesmo em caminho de erro.
9. Revisão por LLM (se disponível, na sessão Claude Code).
10. Relatório final: veredito + evidências organizadas por seção.

## Tratamento de erros e casos de borda

- **Timeout na etapa dinâmica:** VM é destruída do mesmo jeito; relatório registra "análise dinâmica incompleta" como item SUSPICIOUS (never becomes SAFE by default without confirmation).
- **Multipass/hypervisor indisponível:** `repocheck` recusa rodar a etapa dinâmica e avisa claramente que só a análise estática (mais fraca) está disponível — nunca faz fallback silencioso pra clonar no host.
- **Repo privado (exige autenticação):** credenciais/token são passadas só para dentro da VM efêmera, nunca ficam salvas após ela ser destruída, e nunca usa as credenciais git padrão do host sem confirmação explícita.
- **Plataforma desconhecida/self-hosted:** pré-check via API é pulado; pipeline estático/dinâmico dentro da VM continua funcionando normalmente (agnóstico de plataforma).
- **Scanner externo falha/não instalado:** item correspondente fica marcado "não executado", nunca "limpo" — evita falsa sensação de segurança.
- **Repo muito grande:** limite de tamanho/timeout configurável; excede → aborta com aviso.
- **Falha ao destruir a VM:** tenta novamente; se persistir, avisa explicitamente para checagem manual (nunca finge sucesso sem confirmar).

## Estratégia de testes

- **Testes unitários (host, rápidos, sem VM):** parsing de URL/plataforma, lógica do pré-check via API (mockada), parsing do JSON de achados, lógica de composição de veredito a partir de achados simulados.
- **Testes de integração (Multipass real, mais lentos):** contra casos de teste controlados:
  - repo limpo → SAFE;
  - repo com secret hardcoded → pego pelo scanner de secrets;
  - repo com dependência vulnerável conhecida → pego pelo scanner de deps;
  - repo com `postinstall` que tenta conexão de rede → aparece na telemetria mesmo com rede cortada;
  - repo com submódulo/`.gitattributes` malicioso simulado → pego pelas checagens específicas de git;
  - **amostras de ataques reais documentados publicamente** (ex. casos conhecidos de pacotes npm/PyPI maliciosos já removidos, via bases como OSV/relatórios de segurança) — mantidas e manuseadas só dentro da VM efêmera, nunca no host, para validar que o pipeline pega ataques reais e não só simulações artificiais nossas.
- **Teste de ciclo de vida da VM:** garantir que a VM é sempre destruída mesmo forçando timeout/erro no meio da análise.
- **Teste manual da skill:** fluxo ponta a ponta via Claude Code, conferindo que o veredito conversacional bate com o JSON bruto.

## Fora de escopo da v1

- Scanners/heurísticas específicos por gerenciador de pacotes (npm/pip) além do que os scanners agnósticos já cobrem.
- Cache/allowlist de repositórios já analisados como seguros.
- Abstração de múltiplos backends de VM — só Multipass por enquanto.
