"""
PatchForge AI - Phase 7 Docker Sandbox Unit Tests
=================================================
Validates container hardening profiles, memory quotas, ephemeral execution,
stdout/stderr capture, and strict timeout enforcement.
"""

import pytest
from app.sandbox import (
    SandboxSecurityProfile,
    DockerSandboxRunner,
    docker_sandbox_runner,
)


def test_sandbox_security_profile_hardening():
    profile = SandboxSecurityProfile(
        mem_limit="256m",
        network_disabled=True,
        read_only_rootfs=True,
    )
    kwargs = profile.to_container_kwargs()

    assert kwargs["mem_limit"] == "256m"
    assert kwargs["network_mode"] == "none"
    assert kwargs["read_only"] is True
    assert "ALL" in kwargs["cap_drop"]
    assert kwargs["user"] == "1000:1000"
    assert "/tmp" in kwargs["tmpfs"]
    assert kwargs["pids_limit"] == 64


def test_sandbox_runner_basic_python_execution():
    files = {
        "script.py": "print('PatchForge Sandbox OK: ' + str(21 * 2))\n"
    }
    result = docker_sandbox_runner.run_code(
        language="python",
        files=files,
        command="python script.py",
        timeout=10,
    )

    assert result.is_success is True
    assert result.exit_code == 0
    assert "PatchForge Sandbox OK: 42" in result.stdout
    assert result.timed_out is False
    assert result.execution_time_ms > 0


def test_sandbox_runner_multi_file_module_resolution():
    files = {
        "helper.py": "def add(a, b):\n    return a + b\n",
        "main.py": "import helper\nprint('SUM:', helper.add(10, 25))\n",
    }
    result = docker_sandbox_runner.run_code(
        language="python",
        files=files,
        command="python main.py",
        timeout=10,
    )

    assert result.is_success is True
    assert "SUM: 35" in result.stdout


def test_sandbox_runner_error_exit_code_capture():
    files = {
        "failing.py": "import sys\nprint('Starting error test...', file=sys.stderr)\nsys.exit(42)\n"
    }
    result = docker_sandbox_runner.run_code(
        language="python",
        files=files,
        command="python failing.py",
        timeout=10,
    )

    assert result.is_success is False
    assert result.exit_code == 42
    assert "Starting error test..." in result.stderr


def test_sandbox_runner_timeout_enforcement():
    files = {
        "infinite.py": "import time\ntime.sleep(5)\nprint('Done')\n"
    }
    result = docker_sandbox_runner.run_code(
        language="python",
        files=files,
        command="python infinite.py",
        timeout=1,  # 1 second timeout
    )

    assert result.is_success is False
    assert result.timed_out is True
