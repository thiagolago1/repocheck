# Repo Safety Check — Fase 4: Etapa Dinâmica + Telemetria Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Estender o script de análise da Fase 3 para, depois da análise estática, cortar a rede da VM e tentar rodar o passo de build/instalação que o repositório declarar (npm ou pip), capturando via `strace` qualquer tentativa de conexão de rede feita durante essa etapa — mesmo com a rede cortada — e nunca deixando a etapa travar indefinidamente.

**Architecture:** Três funções novas em `repocheck/vm_scripts/analyze.py` (`cut_network`, `detect_build_command`, `run_dynamic_step`) são encadeadas depois dos três scanners estáticos já existentes, dentro de `run()`. A rede só é cortada depois que o clone e os scanners estáticos já rodaram — a etapa dinâmica é a única parte que efetivamente executa código do repositório, então é a única que precisa desse isolamento de rede. O lado do host (`repocheck/src/repocheck/analysis.py`) é atualizado para instalar `nodejs`/`npm`/`strace` no bootstrap da VM e para expor os novos campos no relatório (`AnalysisReport`, renomeado de `StaticAnalysisReport` para refletir que agora cobre estática + dinâmica).

**Tech Stack:** Mesmo da Fase 3 (Python stdlib no script da VM) + `strace` (captura de syscalls, via apt) + `iptables` (corte de rede, já vem com Ubuntu) + `npm`/`pip3` como comandos de build reconhecidos.

## Global Constraints

- A rede só é cortada depois do clone e da análise estática — nunca antes, e sempre antes de qualquer comando de build/instalação ser executado.
- Tentativas de conexão de rede feitas após o corte são capturadas via `strace` e sempre aparecem no relatório — nunca descartadas silenciosamente.
- Se nenhum ecossistema reconhecido for detectado (sem `package.json`/`requirements.txt`/`setup.py`), a etapa dinâmica é pulada explicitamente (`attempted: false`) — nunca tenta adivinhar um comando genérico.
- Timeout na etapa dinâmica marca `timed_out: true` no relatório — nunca trava indefinidamente e nunca vira "limpo" por padrão.
- A VM continua sendo sempre destruída ao final (herdado da Fase 2); o único artefato que sai da VM continua sendo o JSON de achados — nunca o código-fonte nem os binários do repositório.

---

## Task 1: Corte de rede (`cut_network`)

**Files:**
- Modify: `repocheck/vm_scripts/analyze.py`
- Test: `repocheck/tests/test_analyze_script.py`

**Interfaces:**
- Consumes: `analyze.subprocess` (já importado na Fase 3).
- Produces: `analyze.cut_network() -> dict` (retorna `{"applied": bool, "error": str}`).

- [ ] **Step 1: Escrever os testes de corte de rede (devem falhar)**

Adicionar ao final de `repocheck/tests/test_analyze_script.py`:

```python
def test_cut_network_applies_iptables_rules_successfully():
    with patch.object(analyze.subprocess, "run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        result = analyze.cut_network()

    assert result == {"applied": True, "error": ""}
    call_args = mock_run.call_args
    command = call_args.args[0]
    assert command[0] == "sudo"
    assert "iptables" in " ".join(command)


def test_cut_network_reports_failure_when_iptables_fails():
    with patch.object(analyze.subprocess, "run") as mock_run:
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "iptables: command not found"

        result = analyze.cut_network()

    assert result["applied"] is False
    assert "command not found" in result["error"]
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v -k cut_network
```

Expected: FAIL com `AttributeError: module 'analyze' has no attribute 'cut_network'`.

- [ ] **Step 3: Implementar `cut_network`**

Adicionar ao final de `repocheck/vm_scripts/analyze.py`:

```python
def cut_network() -> dict:
    result = subprocess.run(
        [
            "sudo",
            "bash",
            "-c",
            "iptables -P OUTPUT DROP && iptables -A OUTPUT -o lo -j ACCEPT",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {
        "applied": result.returncode == 0,
        "error": "" if result.returncode == 0 else result.stderr.strip(),
    }
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v -k cut_network
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/vm_scripts/analyze.py repocheck/tests/test_analyze_script.py
git commit -m "feat(repocheck): add network cutoff via iptables to the in-VM analysis script"
```

---

## Task 2: Detecção do comando de build/instalação

**Files:**
- Modify: `repocheck/vm_scripts/analyze.py`
- Test: `repocheck/tests/test_analyze_script.py`

**Interfaces:**
- Consumes: nada de tasks anteriores (função independente, só olha o sistema de arquivos).
- Produces: `analyze.detect_build_command(repo_path: pathlib.Path) -> list[str] | None`.

- [ ] **Step 1: Escrever os testes de detecção de build command (devem falhar)**

Adicionar ao final de `repocheck/tests/test_analyze_script.py`:

```python
def test_detect_build_command_finds_npm_for_package_json(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "package.json").write_text('{"name": "example"}')

    command = analyze.detect_build_command(repo_dir)

    assert command == ["npm", "install"]


def test_detect_build_command_finds_pip_for_requirements_txt(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "requirements.txt").write_text("requests==2.31.0\n")

    command = analyze.detect_build_command(repo_dir)

    assert command == ["pip3", "install", "-r", "requirements.txt"]


def test_detect_build_command_finds_pip_for_setup_py(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "setup.py").write_text("from setuptools import setup\nsetup()\n")

    command = analyze.detect_build_command(repo_dir)

    assert command == ["pip3", "install", "."]


def test_detect_build_command_returns_none_for_unrecognized_repo(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello\n")

    command = analyze.detect_build_command(repo_dir)

    assert command is None
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v -k detect_build_command
```

Expected: FAIL com `AttributeError: module 'analyze' has no attribute 'detect_build_command'`.

- [ ] **Step 3: Implementar `detect_build_command`**

Adicionar ao final de `repocheck/vm_scripts/analyze.py`:

```python
def detect_build_command(repo_path: Path) -> list[str] | None:
    if (repo_path / "package.json").is_file():
        return ["npm", "install"]
    if (repo_path / "requirements.txt").is_file():
        return ["pip3", "install", "-r", "requirements.txt"]
    if (repo_path / "setup.py").is_file():
        return ["pip3", "install", "."]
    return None
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v -k detect_build_command
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/vm_scripts/analyze.py repocheck/tests/test_analyze_script.py
git commit -m "feat(repocheck): detect npm/pip build command for the dynamic step"
```

---

## Task 3: Execução da etapa dinâmica com telemetria (`run_dynamic_step`)

**Files:**
- Modify: `repocheck/vm_scripts/analyze.py`
- Test: `repocheck/tests/test_analyze_script.py`

**Interfaces:**
- Consumes: `analyze.detect_build_command`, `analyze.cut_network` (Tasks 1-2, já em `analyze.py`).
- Produces: `analyze.run_dynamic_step(repo_path: pathlib.Path, timeout: float = 120.0) -> dict` (chaves: `attempted: bool`, `command: list[str] | None`, `exit_code: int | None`, `timed_out: bool`, `network_cutoff_applied: bool | None`, `network_connect_attempts: list[str]`).

- [ ] **Step 1: Escrever os testes da etapa dinâmica (devem falhar)**

Adicionar ao final de `repocheck/tests/test_analyze_script.py`:

```python
import subprocess as subprocess_module
from unittest.mock import MagicMock


def test_run_dynamic_step_skips_when_no_build_command_detected(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello\n")

    result = analyze.run_dynamic_step(repo_dir)

    assert result == {
        "attempted": False,
        "command": None,
        "exit_code": None,
        "timed_out": False,
        "network_connect_attempts": [],
    }


def test_run_dynamic_step_runs_detected_command_and_parses_telemetry(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "requirements.txt").write_text("requests==2.31.0\n")
    telemetry_path = repo_dir.parent / "telemetry.log"
    telemetry_path.write_text(
        "connect(3, {sa_family=AF_INET, sin_port=htons(443), "
        'sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ECONNREFUSED\n'
        "openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3\n"
    )

    with patch.object(analyze.subprocess, "run") as mock_run:

        def run_side_effect(command, **kwargs):
            result = MagicMock()
            if command[:2] == ["sudo", "bash"]:
                result.returncode = 0
                result.stderr = ""
            else:
                result.returncode = 0
            return result

        mock_run.side_effect = run_side_effect

        result = analyze.run_dynamic_step(repo_dir, timeout=60.0)

    assert result["attempted"] is True
    assert result["command"] == ["pip3", "install", "-r", "requirements.txt"]
    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert result["network_cutoff_applied"] is True
    assert len(result["network_connect_attempts"]) == 1
    assert "connect(" in result["network_connect_attempts"][0]


def test_run_dynamic_step_marks_timed_out_on_timeout(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "package.json").write_text('{"name": "example"}')

    with patch.object(analyze.subprocess, "run") as mock_run:

        def run_side_effect(command, **kwargs):
            if command[:2] == ["sudo", "bash"]:
                result = MagicMock()
                result.returncode = 0
                result.stderr = ""
                return result
            raise subprocess_module.TimeoutExpired(cmd=command, timeout=60.0)

        mock_run.side_effect = run_side_effect

        result = analyze.run_dynamic_step(repo_dir, timeout=60.0)

    assert result["attempted"] is True
    assert result["timed_out"] is True
    assert result["exit_code"] is None
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v -k run_dynamic_step
```

Expected: FAIL com `AttributeError: module 'analyze' has no attribute 'run_dynamic_step'`.

- [ ] **Step 3: Implementar `run_dynamic_step`**

Adicionar ao final de `repocheck/vm_scripts/analyze.py`:

```python
def run_dynamic_step(repo_path: Path, timeout: float = 120.0) -> dict:
    command = detect_build_command(repo_path)
    if command is None:
        return {
            "attempted": False,
            "command": None,
            "exit_code": None,
            "timed_out": False,
            "network_connect_attempts": [],
        }

    network_result = cut_network()

    telemetry_path = repo_path.parent / "telemetry.log"
    wrapped_command = [
        "strace",
        "-f",
        "-e",
        "trace=connect",
        "-o",
        str(telemetry_path),
        *command,
    ]

    try:
        result = subprocess.run(
            wrapped_command,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        exit_code = result.returncode
        timed_out = False
    except subprocess.TimeoutExpired:
        exit_code = None
        timed_out = True

    connect_attempts = []
    if telemetry_path.is_file():
        for line in telemetry_path.read_text(errors="ignore").splitlines():
            if "connect(" in line:
                connect_attempts.append(line.strip()[:200])

    return {
        "attempted": True,
        "command": command,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "network_cutoff_applied": network_result["applied"],
        "network_connect_attempts": connect_attempts,
    }
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v -k run_dynamic_step
```

Expected: 3 passed.

- [ ] **Step 5: Rodar a suíte completa do arquivo**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v
```

Expected: 24 passed (15 das Fases anteriores + 2 de `cut_network` + 4 de `detect_build_command` + 3 de `run_dynamic_step`).

- [ ] **Step 6: Commit**

```bash
git add repocheck/vm_scripts/analyze.py repocheck/tests/test_analyze_script.py
git commit -m "feat(repocheck): run the dynamic build/install step with strace-based network telemetry"
```

---

## Task 4: Integrar a etapa dinâmica no relatório combinado e na orquestração do host

**Files:**
- Modify: `repocheck/vm_scripts/analyze.py`
- Modify: `repocheck/src/repocheck/analysis.py`
- Modify: `repocheck/tests/test_analyze_script.py`
- Modify: `repocheck/tests/test_analysis.py`
- Modify: `repocheck/tests/test_analysis_integration.py`

**Interfaces:**
- Consumes: `analyze.run_dynamic_step` (Task 3, já em `analyze.py`); `repocheck.vm.EphemeralVM` (Fase 2).
- Produces: `analyze.run()` passa a incluir a chave `"dynamic"` no JSON. `repocheck.analysis.AnalysisReport` (renomeado de `StaticAnalysisReport`, com os campos novos: `dynamic_attempted: bool`, `dynamic_command: list[str] | None`, `dynamic_exit_code: int | None`, `dynamic_timed_out: bool`, `network_cutoff_applied: bool | None`, `network_connect_attempts: list[dict] | list[str]`). `repocheck.analysis.run_analysis(url: str, timeout: float = 300.0) -> AnalysisReport` (renomeado de `run_static_analysis`).

- [ ] **Step 1: Escrever o teste de que `run()` inclui a etapa dinâmica (deve falhar)**

Adicionar ao final de `repocheck/tests/test_analyze_script.py`:

```python
def test_run_includes_dynamic_step_in_combined_report(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello, no build system here\n")
    output_path = tmp_path / "report.json"

    analyze.run(repo_dir, output_path)

    payload = json_module.loads(output_path.read_text())
    assert set(payload.keys()) == {
        "malicious_patterns",
        "git_findings",
        "secrets",
        "dynamic",
    }
    assert payload["dynamic"]["attempted"] is False
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v -k test_run_includes_dynamic_step
```

Expected: FAIL — `payload.keys()` ainda não inclui `"dynamic"`.

- [ ] **Step 3: Atualizar `run()` em `analyze.py`**

Em `repocheck/vm_scripts/analyze.py`, substituir a função `run` existente por:

```python
def run(repo_path: Path, output_path: Path) -> None:
    report = {
        "malicious_patterns": scan_malicious_patterns(repo_path),
        "git_findings": scan_git_specifics(repo_path),
        "secrets": scan_secrets(repo_path),
        "dynamic": run_dynamic_step(repo_path),
    }
    output_path.write_text(json.dumps(report, indent=2))
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

```bash
cd repocheck && .venv/bin/pytest tests/test_analyze_script.py -v
```

Expected: 25 passed.

- [ ] **Step 5: Atualizar a orquestração do host (`repocheck/src/repocheck/analysis.py`)**

Substituir o conteúdo inteiro de `repocheck/src/repocheck/analysis.py` por:

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
    "sudo apt-get install -y -qq git python3-pip nodejs npm strace && "
    "pip3 install --quiet detect-secrets",
]


@dataclass
class AnalysisReport:
    clone_succeeded: bool
    malicious_patterns: list[dict[str, Any]] = field(default_factory=list)
    git_findings: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)
    dynamic_attempted: bool = False
    dynamic_command: list[str] | None = None
    dynamic_exit_code: int | None = None
    dynamic_timed_out: bool = False
    network_cutoff_applied: bool | None = None
    network_connect_attempts: list[str] = field(default_factory=list)
    error: str | None = None


def _local_temp_report_path() -> Path:
    return Path(tempfile.gettempdir()) / f"repocheck-report-{uuid.uuid4().hex}.json"


def run_analysis(url: str, timeout: float = 300.0) -> AnalysisReport:
    with EphemeralVM(launch_timeout=180.0) as vm:
        bootstrap_result = vm.run(_BOOTSTRAP_COMMAND, timeout=240.0)
        if bootstrap_result.returncode != 0:
            return AnalysisReport(
                clone_succeeded=False,
                error=f"bootstrap failed: {bootstrap_result.stderr.strip()}",
            )

        clone_result = vm.run(
            ["git", "clone", "--", url, _REMOTE_REPO_PATH], timeout=timeout
        )
        if clone_result.returncode != 0:
            return AnalysisReport(
                clone_succeeded=False,
                error=f"clone failed: {clone_result.stderr.strip()}",
            )

        vm.push_file(_ANALYZE_SCRIPT, _REMOTE_SCRIPT_PATH)

        analyze_result = vm.run(
            ["python3", _REMOTE_SCRIPT_PATH, _REMOTE_REPO_PATH, _REMOTE_REPORT_PATH],
            timeout=timeout,
        )
        if analyze_result.returncode != 0:
            return AnalysisReport(
                clone_succeeded=True,
                error=f"analysis script failed: {analyze_result.stderr.strip()}",
            )

        local_report_path = _local_temp_report_path()
        vm.pull_file(_REMOTE_REPORT_PATH, local_report_path)
        payload = json.loads(local_report_path.read_text())
        local_report_path.unlink(missing_ok=True)

    dynamic = payload.get("dynamic", {})
    return AnalysisReport(
        clone_succeeded=True,
        malicious_patterns=payload.get("malicious_patterns", []),
        git_findings=payload.get("git_findings", []),
        secrets=payload.get("secrets", []),
        dynamic_attempted=dynamic.get("attempted", False),
        dynamic_command=dynamic.get("command"),
        dynamic_exit_code=dynamic.get("exit_code"),
        dynamic_timed_out=dynamic.get("timed_out", False),
        network_cutoff_applied=dynamic.get("network_cutoff_applied"),
        network_connect_attempts=dynamic.get("network_connect_attempts", []),
    )
```

- [ ] **Step 6: Atualizar `repocheck/tests/test_analysis.py` para usar os novos nomes**

Substituir o conteúdo inteiro de `repocheck/tests/test_analysis.py` por (idêntico ao existente, só trocando `run_static_analysis` por `run_analysis` nos 4 imports/chamadas — nenhuma outra mudança de comportamento; os mocks de `_make_mock_vm` já devolvem um payload JSON sem a chave `"dynamic"`, e o código trata essa ausência com `payload.get("dynamic", {})`, resultando em `dynamic_attempted=False` por padrão):

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
    from repocheck.analysis import run_analysis

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
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is True
    assert report.error is None
    assert len(report.malicious_patterns) == 1
    assert report.malicious_patterns[0]["rule"] == "curl_pipe_shell"
    mock_vm.push_file.assert_called_once()
    mock_vm.pull_file.assert_called_once()


def test_run_static_analysis_bootstrap_failure():
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm(bootstrap_rc=1)
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is False
    assert "bootstrap failed" in report.error
    mock_vm.push_file.assert_not_called()


def test_run_static_analysis_clone_failure():
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm(clone_rc=128)
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/nonexistent")

    assert report.clone_succeeded is False
    assert "clone failed" in report.error


def test_run_static_analysis_script_failure():
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm(analyze_rc=1)
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is True
    assert "analysis script failed" in report.error
```

- [ ] **Step 7: Atualizar `repocheck/tests/test_analysis_integration.py`**

Substituir o conteúdo de `repocheck/tests/test_analysis_integration.py` por:

```python
import pytest

from repocheck.analysis import run_analysis
from repocheck.vm import check_multipass_available

pytestmark = pytest.mark.skipif(
    not check_multipass_available(),
    reason="multipass CLI not installed/available in this environment",
)


def test_analysis_full_pipeline_against_real_public_repo():
    report = run_analysis("https://github.com/octocat/Hello-World", timeout=300.0)

    assert report.clone_succeeded is True
    assert report.error is None
    assert isinstance(report.malicious_patterns, list)
    assert isinstance(report.git_findings, list)
    assert isinstance(report.secrets, list)
    # octocat/Hello-World has no package.json/requirements.txt/setup.py,
    # so the dynamic step must skip explicitly rather than guess a command.
    assert report.dynamic_attempted is False
    assert report.dynamic_command is None
```

- [ ] **Step 8: Rodar a suíte completa e confirmar que passa (ou pula a integração)**

```bash
cd repocheck && .venv/bin/pytest -v
```

Expected: todos os testes passam; o teste de integração real pula (`SKIPPED`) se o Multipass não estiver instalado neste ambiente.

- [ ] **Step 9: Commit**

```bash
git add repocheck/vm_scripts/analyze.py repocheck/src/repocheck/analysis.py repocheck/tests/test_analyze_script.py repocheck/tests/test_analysis.py repocheck/tests/test_analysis_integration.py
git commit -m "feat(repocheck): wire the dynamic step into the combined report and rename to AnalysisReport"
```

---

## Escopo desta fase — o que fica para depois

- Captura de acesso a arquivo fora do diretório do repositório (ex: `~/.ssh`, `/etc`) não está incluída nesta fase — o `strace` desta fase só rastreia `connect()`, não `openat()`/`open()` de forma abrangente. Isso pode ser adicionado numa fase futura se necessário, mas não é essencial para a v1 (o corte de rede já neutraliza o risco mais grave, que é exfiltração).
- Ecossistemas além de npm/pip (ex: Go, Rust/Cargo, Ruby/Bundler) não são reconhecidos nesta fase — `detect_build_command` retorna `None` para eles, e a etapa dinâmica é pulada de forma explícita e seguro (não é um bug, é o comportamento pretendido: nunca adivinhar um comando genérico).
- O veredito final (SEGURO/SUSPEITO/MALICIOSO) ainda não existe — isso é a Fase 5, que combina `PrecheckResult` (Fase 1) com `AnalysisReport` (Fases 3+4, completo agora).
