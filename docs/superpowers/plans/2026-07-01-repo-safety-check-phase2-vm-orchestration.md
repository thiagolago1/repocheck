# Repo Safety Check — Fase 2: Orquestração da VM (Multipass) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar um módulo Python (`repocheck.vm`) que provisiona uma VM Multipass efêmera, executa comandos e transfere arquivos de/para dentro dela, e a destrói sempre ao final — mesmo em caso de erro, timeout, ou falha de destruição — sem nunca deixar uma VM órfã ou cair silenciosamente em execução local.

**Architecture:** Uma classe `EphemeralVM`, implementada como context manager (`with EphemeralVM() as vm: ...`), encapsula todo o ciclo de vida de uma VM Multipass: criação com nome único, execução de comandos via `multipass exec`, transferência de arquivos via `multipass transfer`, e destruição garantida via `__exit__` (com retry e aviso explícito em caso de falha ao destruir). Toda a comunicação com o Multipass acontece via `subprocess.run` com timeout explícito — o módulo nunca invoca a ferramenta `multipass` sem um timeout. As fases seguintes (scanners estáticos, etapa dinâmica) vão consumir esta classe sem precisar conhecer os detalhes do Multipass.

**Tech Stack:** Python >= 3.11 (mesmo pacote `repocheck` da Fase 1), `subprocess`/`shutil`/`uuid`/`warnings`/`pathlib`/`dataclasses` da biblioteca padrão (nenhuma dependência nova), Multipass como CLI externa (não é uma dependência Python).

## Global Constraints

- A VM é sempre destruída ao final do uso do context manager — inclusive quando o bloco `with` levanta uma exceção (erro, timeout, etc). Nunca deixa uma VM órfã por omissão de código.
- Cada análise usa uma VM nova, com nome único — nunca reaproveita uma instância de uma análise anterior.
- Se o Multipass não estiver instalado ou não estiver funcional, o módulo falha explicitamente (`MultipassNotAvailable`) — nunca cai em fallback silencioso para rodar comandos localmente no host.
- Toda chamada de `subprocess` para o CLI do `multipass` tem um timeout explícito — nenhuma chamada pode bloquear indefinidamente.
- Se destruir a VM falhar, o código tenta novamente uma vez; se persistir, avisa explicitamente (levanta `VMCleanupError` se não havia outra exceção em andamento, ou emite um `warnings.warn` sem mascarar uma exceção original já em propagação) — nunca finge sucesso silenciosamente.
- O módulo vive em `repocheck/src/repocheck/vm.py`, dentro do mesmo pacote `repocheck` já existente da Fase 1.

---

## Task 1: Detecção de disponibilidade do Multipass

**Files:**
- Create: `repocheck/src/repocheck/vm.py`
- Test: `repocheck/tests/test_vm.py`

**Interfaces:**
- Consumes: nada de fases anteriores.
- Produces: `repocheck.vm.MultipassNotAvailable` (exception), `repocheck.vm.check_multipass_available() -> bool`.

- [ ] **Step 1: Escrever o teste de detecção de disponibilidade (deve falhar)**

Criar `repocheck/tests/test_vm.py`:

```python
import subprocess
from unittest.mock import patch

from repocheck.vm import check_multipass_available


def test_returns_false_when_multipass_binary_not_found():
    with patch("repocheck.vm.shutil.which", return_value=None) as mock_which:
        assert check_multipass_available() is False
    mock_which.assert_called_once_with("multipass")


def test_returns_true_when_multipass_version_succeeds():
    with patch("repocheck.vm.shutil.which", return_value="/usr/local/bin/multipass"):
        with patch("repocheck.vm.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            assert check_multipass_available() is True
    mock_run.assert_called_once_with(
        ["multipass", "version"], capture_output=True, text=True, timeout=5
    )


def test_returns_false_when_multipass_version_fails():
    with patch("repocheck.vm.shutil.which", return_value="/usr/local/bin/multipass"):
        with patch("repocheck.vm.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            assert check_multipass_available() is False


def test_returns_false_when_version_check_times_out():
    with patch("repocheck.vm.shutil.which", return_value="/usr/local/bin/multipass"):
        with patch(
            "repocheck.vm.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="multipass version", timeout=5),
        ):
            assert check_multipass_available() is False


def test_returns_false_when_version_check_raises_os_error():
    with patch("repocheck.vm.shutil.which", return_value="/usr/local/bin/multipass"):
        with patch("repocheck.vm.subprocess.run", side_effect=OSError("boom")):
            assert check_multipass_available() is False
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_vm.py -v
```

Expected: FAIL com `ModuleNotFoundError: No module named 'repocheck.vm'`.

- [ ] **Step 3: Implementar `check_multipass_available`**

Criar `repocheck/src/repocheck/vm.py`:

```python
import shutil
import subprocess


class MultipassNotAvailable(Exception):
    pass


def check_multipass_available() -> bool:
    if shutil.which("multipass") is None:
        return False
    try:
        result = subprocess.run(
            ["multipass", "version"], capture_output=True, text=True, timeout=5
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_vm.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/src/repocheck/vm.py repocheck/tests/test_vm.py
git commit -m "feat(repocheck): detect Multipass CLI availability"
```

---

## Task 2: Ciclo de vida da VM (launch/destroy via context manager)

**Files:**
- Modify: `repocheck/src/repocheck/vm.py`
- Test: `repocheck/tests/test_vm.py`

**Interfaces:**
- Consumes: `repocheck.vm.check_multipass_available` (Task 1, já em `vm.py`).
- Produces: `repocheck.vm.DEFAULT_IMAGE` (`str`), `repocheck.vm.VMLaunchError` (exception), `repocheck.vm.VMCleanupError` (exception), `repocheck.vm.EphemeralVM` (classe com `__init__(self, image: str = DEFAULT_IMAGE, launch_timeout: float = 120.0)`, `self.name: str` único, `__enter__(self) -> "EphemeralVM"`, `__exit__(self, exc_type, exc_value, traceback) -> bool`).

- [ ] **Step 1: Escrever os testes do ciclo de vida (devem falhar)**

Adicionar ao final de `repocheck/tests/test_vm.py`:

```python
import warnings

import pytest

from repocheck.vm import (
    DEFAULT_IMAGE,
    EphemeralVM,
    MultipassNotAvailable,
    VMCleanupError,
    VMLaunchError,
)


def _mock_completed(returncode=0, stdout="", stderr=""):
    result = subprocess.CompletedProcess(args=[], returncode=returncode)
    result.stdout = stdout
    result.stderr = stderr
    return result


def test_enter_raises_when_multipass_unavailable():
    with patch("repocheck.vm.check_multipass_available", return_value=False):
        with patch("repocheck.vm.subprocess.run") as mock_run:
            with pytest.raises(MultipassNotAvailable):
                with EphemeralVM():
                    pass
    mock_run.assert_not_called()


def test_enter_launches_vm_with_correct_command():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        with patch(
            "repocheck.vm.subprocess.run", return_value=_mock_completed(returncode=0)
        ) as mock_run:
            with EphemeralVM(image="24.04", launch_timeout=60.0) as vm:
                launch_name = vm.name

    launch_call = mock_run.call_args_list[0]
    assert launch_call.args[0] == [
        "multipass", "launch", "24.04", "--name", launch_name,
        "--timeout", "60",
    ]
    assert launch_call.kwargs["timeout"] == 90.0


def test_enter_raises_vm_launch_error_on_nonzero_exit():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        with patch(
            "repocheck.vm.subprocess.run",
            return_value=_mock_completed(returncode=1, stderr="no images available"),
        ):
            with pytest.raises(VMLaunchError, match="no images available"):
                with EphemeralVM():
                    pass


def test_exit_always_calls_delete_with_purge():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        with patch(
            "repocheck.vm.subprocess.run", return_value=_mock_completed(returncode=0)
        ) as mock_run:
            with EphemeralVM() as vm:
                name = vm.name

    delete_call = mock_run.call_args_list[-1]
    assert delete_call.args[0] == ["multipass", "delete", name, "--purge"]


def test_exit_destroys_vm_even_when_block_raises():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        with patch(
            "repocheck.vm.subprocess.run", return_value=_mock_completed(returncode=0)
        ) as mock_run:
            with pytest.raises(RuntimeError, match="boom"):
                with EphemeralVM() as vm:
                    name = vm.name
                    raise RuntimeError("boom")

    delete_call = mock_run.call_args_list[-1]
    assert delete_call.args[0] == ["multipass", "delete", name, "--purge"]


def test_exit_retries_delete_once_on_failure():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),   # launch
            _mock_completed(returncode=1, stderr="busy"),  # delete attempt 1
            _mock_completed(returncode=0),   # delete attempt 2 (retry succeeds)
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses) as mock_run:
            with EphemeralVM():
                pass

    assert mock_run.call_count == 3


def test_exit_raises_cleanup_error_when_delete_fails_twice_and_no_other_exception():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),   # launch
            _mock_completed(returncode=1, stderr="busy"),  # delete attempt 1
            _mock_completed(returncode=1, stderr="still busy"),  # delete attempt 2
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with pytest.raises(VMCleanupError, match="still busy"):
                with EphemeralVM():
                    pass


def test_exit_warns_instead_of_masking_original_exception():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),   # launch
            _mock_completed(returncode=1, stderr="busy"),  # delete attempt 1
            _mock_completed(returncode=1, stderr="still busy"),  # delete attempt 2
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with pytest.warns(RuntimeWarning, match="still busy"):
                with pytest.raises(RuntimeError, match="original error"):
                    with EphemeralVM():
                        raise RuntimeError("original error")
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_vm.py -v
```

Expected: FAIL com `ImportError: cannot import name 'EphemeralVM' from 'repocheck.vm'` (e demais nomes ainda não definidos).

- [ ] **Step 3: Implementar `EphemeralVM` (launch/destroy)**

Adicionar ao final de `repocheck/src/repocheck/vm.py` (mantendo o que já existe de `MultipassNotAvailable`/`check_multipass_available`, e adicionando `import uuid` e `import warnings` ao topo do arquivo junto aos imports já existentes de `shutil`/`subprocess`):

```python
import uuid
import warnings


class VMLaunchError(Exception):
    pass


class VMCleanupError(Exception):
    pass


DEFAULT_IMAGE = "24.04"


class EphemeralVM:
    def __init__(self, image: str = DEFAULT_IMAGE, launch_timeout: float = 120.0):
        self.image = image
        self.launch_timeout = launch_timeout
        self.name = f"repocheck-{uuid.uuid4().hex[:12]}"

    def __enter__(self) -> "EphemeralVM":
        if not check_multipass_available():
            raise MultipassNotAvailable(
                "multipass CLI not found or not working; install it to run "
                "the dynamic analysis stage"
            )
        result = subprocess.run(
            [
                "multipass", "launch", self.image, "--name", self.name,
                "--timeout", str(int(self.launch_timeout)),
            ],
            capture_output=True,
            text=True,
            timeout=self.launch_timeout + 30,
        )
        if result.returncode != 0:
            raise VMLaunchError(
                f"failed to launch multipass VM '{self.name}': {result.stderr.strip()}"
            )
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        delete_result = subprocess.run(
            ["multipass", "delete", self.name, "--purge"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if delete_result.returncode != 0:
            retry_result = subprocess.run(
                ["multipass", "delete", self.name, "--purge"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if retry_result.returncode != 0:
                message = (
                    f"failed to destroy VM '{self.name}' after retry; "
                    f"check manually with 'multipass list': {retry_result.stderr.strip()}"
                )
                if exc_type is None:
                    raise VMCleanupError(message)
                warnings.warn(message, RuntimeWarning, stacklevel=2)
        return False
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_vm.py -v
```

Expected: 13 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/src/repocheck/vm.py repocheck/tests/test_vm.py
git commit -m "feat(repocheck): add EphemeralVM launch/destroy lifecycle"
```

---

## Task 3: Execução de comandos dentro da VM

**Files:**
- Modify: `repocheck/src/repocheck/vm.py`
- Test: `repocheck/tests/test_vm.py`

**Interfaces:**
- Consumes: `repocheck.vm.EphemeralVM` (Task 2, já em `vm.py`).
- Produces: `repocheck.vm.VMCommandResult` (dataclass com `returncode: int`, `stdout: str`, `stderr: str`), `repocheck.vm.VMCommandTimeout` (exception), `EphemeralVM.run(self, command: list[str], timeout: float = 60.0) -> VMCommandResult`.

- [ ] **Step 1: Escrever os testes de execução de comando (devem falhar)**

Adicionar ao final de `repocheck/tests/test_vm.py`:

```python
from repocheck.vm import VMCommandResult, VMCommandTimeout


def test_run_executes_command_and_returns_result():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=0, stdout="hello\n", stderr=""),  # run
            _mock_completed(returncode=0),  # delete
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses) as mock_run:
            with EphemeralVM() as vm:
                name = vm.name
                result = vm.run(["echo", "hello"], timeout=10.0)

    assert result == VMCommandResult(returncode=0, stdout="hello\n", stderr="")
    run_call = mock_run.call_args_list[1]
    assert run_call.args[0] == ["multipass", "exec", name, "--", "echo", "hello"]
    assert run_call.kwargs["timeout"] == 10.0


def test_run_raises_vm_command_timeout_on_subprocess_timeout():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=0),  # delete (runs after the nested patch below reverts)
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with EphemeralVM() as vm:
                with patch(
                    "repocheck.vm.subprocess.run",
                    side_effect=subprocess.TimeoutExpired(cmd="multipass exec", timeout=10.0),
                ):
                    with pytest.raises(VMCommandTimeout):
                        vm.run(["sleep", "999"], timeout=10.0)
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_vm.py -v
```

Expected: FAIL com `ImportError: cannot import name 'VMCommandResult' from 'repocheck.vm'`.

- [ ] **Step 3: Implementar `VMCommandResult`, `VMCommandTimeout` e `EphemeralVM.run`**

Adicionar `from dataclasses import dataclass` aos imports no topo de `repocheck/src/repocheck/vm.py`. Adicionar a dataclass e a exceção logo após `VMCleanupError`, e o método `run` dentro da classe `EphemeralVM` (após `__exit__`):

```python
@dataclass
class VMCommandResult:
    returncode: int
    stdout: str
    stderr: str


class VMCommandTimeout(Exception):
    pass
```

Dentro de `EphemeralVM`, adicionar o método:

```python
    def run(self, command: list[str], timeout: float = 60.0) -> VMCommandResult:
        try:
            result = subprocess.run(
                ["multipass", "exec", self.name, "--", *command],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise VMCommandTimeout(
                f"command timed out after {timeout}s inside VM '{self.name}': {command}"
            ) from exc
        return VMCommandResult(
            returncode=result.returncode, stdout=result.stdout, stderr=result.stderr
        )
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_vm.py -v
```

Expected: 15 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/src/repocheck/vm.py repocheck/tests/test_vm.py
git commit -m "feat(repocheck): add EphemeralVM.run for executing commands inside the VM"
```

---

## Task 4: Transferência de arquivos de/para a VM

**Files:**
- Modify: `repocheck/src/repocheck/vm.py`
- Test: `repocheck/tests/test_vm.py`

**Interfaces:**
- Consumes: `repocheck.vm.EphemeralVM` (Tasks 2-3, já em `vm.py`).
- Produces: `repocheck.vm.VMTransferError` (exception), `EphemeralVM.push_file(self, local_path: pathlib.Path, remote_path: str) -> None`, `EphemeralVM.pull_file(self, remote_path: str, local_path: pathlib.Path) -> None`.

- [ ] **Step 1: Escrever os testes de transferência de arquivo (devem falhar)**

Adicionar ao final de `repocheck/tests/test_vm.py`:

```python
from pathlib import Path

from repocheck.vm import VMTransferError


def test_push_file_calls_multipass_transfer_with_correct_args():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=0),  # transfer
            _mock_completed(returncode=0),  # delete
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses) as mock_run:
            with EphemeralVM() as vm:
                name = vm.name
                vm.push_file(Path("/tmp/analyze.py"), "/home/ubuntu/analyze.py")

    transfer_call = mock_run.call_args_list[1]
    assert transfer_call.args[0] == [
        "multipass", "transfer", "/tmp/analyze.py", f"{name}:/home/ubuntu/analyze.py",
    ]


def test_push_file_raises_vm_transfer_error_on_failure():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=1, stderr="no such file"),  # transfer
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with EphemeralVM() as vm:
                with pytest.raises(VMTransferError, match="no such file"):
                    vm.push_file(Path("/tmp/missing.py"), "/home/ubuntu/missing.py")


def test_pull_file_calls_multipass_transfer_with_correct_args():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=0),  # transfer
            _mock_completed(returncode=0),  # delete
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses) as mock_run:
            with EphemeralVM() as vm:
                name = vm.name
                vm.pull_file("/home/ubuntu/report.json", Path("/tmp/report.json"))

    transfer_call = mock_run.call_args_list[1]
    assert transfer_call.args[0] == [
        "multipass", "transfer", f"{name}:/home/ubuntu/report.json", "/tmp/report.json",
    ]


def test_pull_file_raises_vm_transfer_error_on_failure():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=1, stderr="permission denied"),  # transfer
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with EphemeralVM() as vm:
                with pytest.raises(VMTransferError, match="permission denied"):
                    vm.pull_file("/home/ubuntu/report.json", Path("/tmp/report.json"))
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_vm.py -v
```

Expected: FAIL com `ImportError: cannot import name 'VMTransferError' from 'repocheck.vm'`.

- [ ] **Step 3: Implementar `VMTransferError`, `push_file` e `pull_file`**

Adicionar `from pathlib import Path` aos imports no topo de `repocheck/src/repocheck/vm.py`. Adicionar a exceção logo após `VMCommandTimeout`:

```python
class VMTransferError(Exception):
    pass
```

Dentro de `EphemeralVM`, adicionar os métodos (após `run`):

```python
    def push_file(self, local_path: Path, remote_path: str) -> None:
        result = subprocess.run(
            ["multipass", "transfer", str(local_path), f"{self.name}:{remote_path}"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise VMTransferError(
                f"failed to push {local_path} to VM '{self.name}:{remote_path}': "
                f"{result.stderr.strip()}"
            )

    def pull_file(self, remote_path: str, local_path: Path) -> None:
        result = subprocess.run(
            ["multipass", "transfer", f"{self.name}:{remote_path}", str(local_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise VMTransferError(
                f"failed to pull VM '{self.name}:{remote_path}' to {local_path}: "
                f"{result.stderr.strip()}"
            )
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_vm.py -v
```

Expected: 19 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/src/repocheck/vm.py repocheck/tests/test_vm.py
git commit -m "feat(repocheck): add EphemeralVM.push_file/pull_file for file transfer"
```

---

## Task 5: Teste de integração real (ciclo completo com Multipass de verdade)

**Files:**
- Test: `repocheck/tests/test_vm_integration.py`

**Interfaces:**
- Consumes: `repocheck.vm.EphemeralVM`, `repocheck.vm.check_multipass_available` (Tasks 1-4, já completas).
- Produces: nada de novo em produção — só um teste de integração que valida o ciclo real de vida da VM contra o Multipass instalado de verdade (ou é pulado quando o Multipass não está disponível no ambiente).

Este teste é separado dos demais (arquivo próprio `test_vm_integration.py`, não `test_vm.py`) porque ele é lento (sobe e derruba uma VM real) e depende de uma ferramenta externa instalada — os testes das Tasks 1-4 (mockados) continuam sendo a suíte rápida e sempre executável que valida a lógica do módulo.

- [ ] **Step 1: Escrever o teste de integração**

Criar `repocheck/tests/test_vm_integration.py`:

```python
from pathlib import Path

import pytest

from repocheck.vm import EphemeralVM, check_multipass_available

pytestmark = pytest.mark.skipif(
    not check_multipass_available(),
    reason="multipass CLI not installed/available in this environment",
)


def test_full_lifecycle_launch_run_transfer_destroy(tmp_path):
    local_input = tmp_path / "input.txt"
    local_input.write_text("hello from host\n")
    local_output = tmp_path / "output.txt"

    with EphemeralVM(launch_timeout=180.0) as vm:
        vm_name = vm.name

        vm.push_file(local_input, "/home/ubuntu/input.txt")

        result = vm.run(["cat", "/home/ubuntu/input.txt"], timeout=30.0)
        assert result.returncode == 0
        assert result.stdout == "hello from host\n"

        vm.run(
            ["cp", "/home/ubuntu/input.txt", "/home/ubuntu/output.txt"], timeout=30.0
        )
        vm.pull_file("/home/ubuntu/output.txt", local_output)

    assert local_output.read_text() == "hello from host\n"

    # Confirm the VM is really gone after the context manager exits.
    import subprocess

    list_result = subprocess.run(
        ["multipass", "list", "--format", "csv"], capture_output=True, text=True, timeout=30
    )
    assert vm_name not in list_result.stdout
```

- [ ] **Step 2: Rodar o teste**

```bash
cd repocheck && .venv/bin/pytest tests/test_vm_integration.py -v
```

Expected: se o Multipass não estiver instalado neste ambiente, `SKIPPED (multipass CLI not installed/available in this environment)`. Se estiver instalado, o teste sobe uma VM Ubuntu real (pode levar de 1 a 3 minutos na primeira vez, por causa do download da imagem), executa o ciclo completo, e passa (`1 passed`). Ambos os resultados são aceitáveis nesta etapa — o importante é confirmar que ele não FALHA (erro), apenas passa ou pula.

- [ ] **Step 3: Rodar a suíte completa do projeto**

```bash
cd repocheck && .venv/bin/pytest -v
```

Expected: todos os testes das Fases 1 e 2 passam (Fase 1: 34 testes; Fase 2, Tasks 1-4: 19 testes; Task 5: 1 passed ou 1 skipped, dependendo do ambiente).

- [ ] **Step 4: Commit**

```bash
git add repocheck/tests/test_vm_integration.py
git commit -m "test(repocheck): add real Multipass end-to-end lifecycle integration test"
```

---

## Escopo desta fase — o que fica para depois

- Nenhum script de análise (clone, scanners estáticos, etapa dinâmica) roda dentro da VM ainda — isso é a Fase 3 (scanners estáticos) e Fase 4 (etapa dinâmica + telemetria), que vão consumir `EphemeralVM.push_file`/`run`/`pull_file` para executar o script de análise real.
- Corte de rede dentro da VM (a política "rede só durante o clone, depois corta") também é responsabilidade do script de análise das Fases 3/4, não deste módulo de orquestração — este módulo só sobe/derruba a VM e move comandos/arquivos de um lado para o outro.
- Um teste de "chaos" mais elaborado (matar o processo do host no meio de uma análise em andamento e confirmar que não sobra VM órfã) fica para quando houver uma carga de trabalho real de análise rodando dentro da VM (Fases 3/4) — os testes desta fase já cobrem, de forma mockada, que o `__exit__` sempre roda mesmo quando o bloco `with` levanta uma exceção.
