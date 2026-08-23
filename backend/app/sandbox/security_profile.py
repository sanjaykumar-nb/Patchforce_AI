"""
PatchForge AI - Sandbox Security Profile & Isolation Policy
===========================================================
Defines the strict isolation constraints (least privilege, cgroups quotas,
network disabling, dropped capabilities, and read-only rootfs) for Docker sandboxes.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List
from app.config import get_settings

settings = get_settings()


@dataclass
class SandboxSecurityProfile:
    """Hardened security boundary for ephemeral container execution."""
    mem_limit: str = settings.SANDBOX_MEMORY_LIMIT
    nano_cpus: int = int(settings.SANDBOX_CPU_QUOTA * 1_000_000_000)
    pids_limit: int = 64
    network_disabled: bool = settings.SANDBOX_NETWORK_DISABLED
    read_only_rootfs: bool = True
    cap_drop: List[str] = field(default_factory=lambda: ["ALL"])
    security_opt: List[str] = field(default_factory=lambda: ["no-new-privileges:true"])
    user: str = "1000:1000"
    timeout_seconds: int = settings.SANDBOX_TIMEOUT_SECONDS
    tmpfs: Dict[str, str] = field(default_factory=lambda: {
        "/tmp": "rw,exec,nosuid,size=128m",
    })

    def to_container_kwargs(self) -> Dict[str, Any]:
        """Converts security profile into Docker SDK container creation arguments."""
        kwargs: Dict[str, Any] = {
            "mem_limit": self.mem_limit,
            "nano_cpus": self.nano_cpus,
            "pids_limit": self.pids_limit,
            "network_mode": "none" if self.network_disabled else "bridge",
            "read_only": self.read_only_rootfs,
            "cap_drop": self.cap_drop,
            "security_opt": self.security_opt,
            "user": self.user,
            "tmpfs": self.tmpfs,
            "working_dir": "/tmp",
            "detach": True,
            "stdout": True,
            "stderr": True,
        }
        return kwargs
