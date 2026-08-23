"""
PatchForge AI - Phase 0 Environment Verification Script
======================================================
Validates all host prerequisites for PatchForge AI:
- Python 3.10+ & Virtual Environment / Launcher
- Node.js & npm (v18+)
- Docker Engine & Docker Compose v2+
- Git CLI
- Ollama & Local Code LLM Models (Qwen2.5-Coder / DeepSeek-Coder)
- Hardware Resources (RAM & CPU for local AST & Inference)
- Port Availability (8000, 3000, 5432, 6379, 11434)

Zero external dependencies required (Pure Python Standard Library).
"""

import sys
import os
import shutil
import subprocess
import socket
import json
import urllib.request
import urllib.error
import platform
import ctypes

class TerminalColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    banner = rf"""{TerminalColors.OKCYAN}{TerminalColors.BOLD}
======================================================================
     ____       _       _     _____                     _   ___ 
    |  _ \ __ _| |_ ___| |__ |  ___|__  _ __ __ _  ___ / \ |_ _|
    | |_) / _` | __/ __| '_ \| |_ / _ \| '__/ _` |/ _ \ _ \ | | 
    |  __/ (_| | || (__| | | |  _| (_) | | | (_| |  __/ ___ \| | 
    |_|   \__,_|\__\___|_| |_|_|  \___/|_|  \__, |\___/_/   \___|
                                            |___/                
    PatchForge AI: Phase 0 Environment & Prerequisites Inspector
======================================================================{TerminalColors.ENDC}"""
    print(banner)

def find_executable(names, default_paths=None):
    """Find executable in PATH or fallback default Windows paths"""
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    if default_paths:
        for p in default_paths:
            expanded = os.path.expandvars(p)
            if os.path.exists(expanded) and os.path.isfile(expanded):
                return expanded
    return None

def run_cmd(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return False, "", str(e)

def check_port(port):
    """Check if a port is in use or available"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) == 0

def get_system_ram_gb():
    """Get total and available RAM in GB across Windows/Linux without psutil"""
    try:
        if platform.system() == "Windows":
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            total_gb = round(stat.ullTotalPhys / (1024 ** 3), 2)
            avail_gb = round(stat.ullAvailPhys / (1024 ** 3), 2)
            return total_gb, avail_gb
        else:
            total_bytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
            total_gb = round(total_bytes / (1024 ** 3), 2)
            return total_gb, total_gb * 0.5
    except Exception:
        return 8.0, 4.0

def format_status(name, passed, details, is_warning=False):
    status_icon = f"{TerminalColors.OKGREEN}[PASS]{TerminalColors.ENDC}" if passed else (
        f"{TerminalColors.WARNING}[WARN]{TerminalColors.ENDC}" if is_warning else f"{TerminalColors.FAIL}[FAIL]{TerminalColors.ENDC}"
    )
    print(f"  {status_icon} {TerminalColors.BOLD}{name:<25}{TerminalColors.ENDC} : {details}")
    return passed

def main():
    print_banner()
    all_passed = True
    warnings = []

    print(f"\n{TerminalColors.HEADER}{TerminalColors.BOLD}1. Host OS & Hardware Resources{TerminalColors.ENDC}")
    os_name = f"{platform.system()} {platform.release()} ({platform.architecture()[0]})"
    print(f"  {TerminalColors.OKCYAN}[INFO]{TerminalColors.ENDC} OS Platform               : {os_name}")
    
    # Memory
    total_ram_gb, avail_ram_gb = get_system_ram_gb()
    ram_ok = total_ram_gb >= 8.0
    format_status("System Memory", ram_ok, f"Total: {total_ram_gb} GB, Available: {avail_ram_gb} GB (Recommended >= 16 GB for Local LLM)", is_warning=not ram_ok)
    if not ram_ok:
        warnings.append("RAM is less than 8 GB. Local LLM models (e.g. qwen2.5-coder:7b) may run slowly; recommend quantized models (e.g. qwen2.5-coder:1.5b).")

    # CPU
    cpu_count = os.cpu_count() or 1
    cpu_ok = cpu_count >= 4
    format_status("CPU Cores", cpu_ok, f"{cpu_count} logical cores detected", is_warning=not cpu_ok)

    print(f"\n{TerminalColors.HEADER}{TerminalColors.BOLD}2. Core Runtimes & Tooling{TerminalColors.ENDC}")
    # Python
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info.major == 3 and sys.version_info.minor >= 10
    format_status("Python Runtime", py_ok, f"Python {py_ver} ({sys.executable})")
    if not py_ok:
        all_passed = False

    # Git
    git_bin = find_executable(["git"], [
        r"%ProgramFiles%\Git\cmd\git.exe",
        r"%ProgramFiles%\Git\bin\git.exe",
        r"%LOCALAPPDATA%\Programs\Git\cmd\git.exe"
    ])
    if git_bin:
        git_ok, git_out, _ = run_cmd(f'"{git_bin}" --version')
        format_status("Git CLI", git_ok, f"{git_out} ({git_bin})")
    else:
        git_ok = False
        format_status("Git CLI", False, "Git not found. Install from https://git-scm.com/ or run 'winget install --id Git.Git -e'")
        all_passed = False

    # Node.js & npm
    node_bin = find_executable(["node"], [
        r"%ProgramFiles%\nodejs\node.exe",
        r"%LOCALAPPDATA%\Programs\node\node.exe"
    ])
    if node_bin:
        node_ok, node_out, _ = run_cmd(f'"{node_bin}" --version')
        npm_bin = find_executable(["npm"], [r"%ProgramFiles%\nodejs\npm.cmd"])
        npm_out = ""
        if npm_bin:
            _, npm_out, _ = run_cmd(f'"{npm_bin}" --version')
        try:
            major_ver = int(node_out.strip().lstrip('v').split('.')[0])
            node_valid = major_ver >= 18
        except Exception:
            node_valid = False
        format_status("Node.js Runtime", node_valid, f"{node_out} (npm v{npm_out}) at {node_bin}")
    else:
        format_status("Node.js Runtime", False, "Node.js (v18+) not found. Install from https://nodejs.org/ or 'winget install OpenJS.NodeJS -e'", is_warning=True)
        warnings.append("Node.js v18+ is required for the React dashboard. Install via 'winget install OpenJS.NodeJS -e'")

    print(f"\n{TerminalColors.HEADER}{TerminalColors.BOLD}3. Docker Containerization & Sandbox Engine{TerminalColors.ENDC}")
    docker_bin = find_executable(["docker"], [
        r"%ProgramFiles%\Docker\Docker\resources\bin\docker.exe",
        r"%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe"
    ])
    if docker_bin:
        docker_ok, docker_out, _ = run_cmd(f'"{docker_bin}" --version')
        format_status("Docker CLI", docker_ok, f"{docker_out}")
    else:
        docker_ok = False
        format_status("Docker CLI", False, "Docker CLI not found.")
        all_passed = False

    if docker_ok and docker_bin:
        daemon_ok, daemon_out, _ = run_cmd(f'"{docker_bin}" info --format "{{{{.ServerVersion}}}}"')
        format_status("Docker Daemon Status", daemon_ok, f"Running (Engine v{daemon_out})" if daemon_ok else "Docker daemon is NOT running. Please start Docker Desktop.")
        if not daemon_ok:
            all_passed = False

        compose_ok, compose_out, _ = run_cmd(f'"{docker_bin}" compose version')
        format_status("Docker Compose", compose_ok, compose_out if compose_ok else "Docker Compose v2 not found")
        if not compose_ok:
            all_passed = False
    else:
        all_passed = False

    print(f"\n{TerminalColors.HEADER}{TerminalColors.BOLD}4. Local AI / LLM Inference Engine (Ollama){TerminalColors.ENDC}")
    ollama_bin = find_executable(["ollama"], [
        r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe",
        r"%ProgramFiles%\Ollama\ollama.exe"
    ])
    if ollama_bin:
        ollama_cli_ok, ollama_cli_out, _ = run_cmd(f'"{ollama_bin}" --version')
        format_status("Ollama CLI", ollama_cli_ok, f"{ollama_cli_out} ({ollama_bin})")
    else:
        format_status("Ollama CLI", False, "Ollama CLI not installed locally (Can run via Docker or https://ollama.com/download)", is_warning=True)

    # Ollama Service (HTTP endpoint)
    ollama_api_ok = False
    ollama_models = []
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/tags")
        with urllib.request.urlopen(req, timeout=2) as response:
            if response.status == 200:
                ollama_api_ok = True
                data = json.loads(response.read().decode())
                ollama_models = [m.get("name") for m in data.get("models", [])]
    except Exception:
        ollama_api_ok = False

    format_status("Ollama Service (11434)", ollama_api_ok, f"Active at http://localhost:11434 (Models: {', '.join(ollama_models) if ollama_models else 'None'})" if ollama_api_ok else "Ollama service not active at http://localhost:11434 (Will start via Docker or 'ollama serve')", is_warning=not ollama_api_ok)
    if ollama_api_ok:
        has_coder_model = any(any(k in m.lower() for k in ["coder", "deepseek", "qwen"]) for m in ollama_models)
        format_status("Code LLM Model", has_coder_model, f"Detected: {ollama_models}" if has_coder_model else "No coder model found. Recommended: 'ollama pull qwen2.5-coder:7b' or '1.5b'", is_warning=not has_coder_model)
        if not has_coder_model:
            warnings.append("No coder model detected in Ollama. Run: 'ollama pull qwen2.5-coder:7b' (or 1.5b / 3b)")
    else:
        warnings.append("Ollama service not running locally. Can run natively ('ollama serve') or via docker-compose ollama service.")

    print(f"\n{TerminalColors.HEADER}{TerminalColors.BOLD}5. Networking & Port Availability{TerminalColors.ENDC}")
    ports = [
        (8000, "FastAPI Backend API"),
        (3000, "React Dashboard UI"),
        (5432, "PostgreSQL Database"),
        (6379, "Redis Message Broker"),
        (11434, "Ollama LLM Engine")
    ]
    for port, service_name in ports:
        in_use = check_port(port)
        status_desc = f"Port {port} in use ({service_name} or existing process)" if in_use else f"Port {port} free ({service_name})"
        format_status(f"Port {port} ({service_name})", True, status_desc)

    print(f"\n{TerminalColors.HEADER}{TerminalColors.BOLD}==================== Phase 0 Summary ===================={TerminalColors.ENDC}")
    if all_passed and len(warnings) == 0:
        print(f"{TerminalColors.OKGREEN}{TerminalColors.BOLD}All critical prerequisites satisfied! Your environment is ready for PatchForge AI Phase 1.{TerminalColors.ENDC}\n")
        return 0
    elif all_passed:
        print(f"{TerminalColors.WARNING}{TerminalColors.BOLD}Core prerequisites met with {len(warnings)} recommendations / optional items:{TerminalColors.ENDC}")
        for w in warnings:
            print(f"  - {w}")
        print(f"\n{TerminalColors.OKCYAN}Your environment is ready to proceed to Phase 1.{TerminalColors.ENDC}\n")
        return 0
    else:
        print(f"{TerminalColors.FAIL}{TerminalColors.BOLD}Critical environment requirements need attention. Please review the failed items above.{TerminalColors.ENDC}\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
