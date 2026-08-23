"""
PatchForge AI - Vulnerability Source File Resolver
===================================================
Resolves the on-disk location of the file a Vulnerability finding came from.

Vulnerability.file_path is stored relative to whatever directory was scanned
(see SecurityScanner.scan_directory), not relative to the process CWD. Re-reading
the file later (for patch generation / validation) therefore requires the scan's
recorded root directory, which is why every Scan persists `repo_path`. Older scans
predating that column (or scans that legitimately targeted the bundled fixtures)
fall back to the CWD and the fixtures directories.
"""

import os
from typing import Optional

from app.models.vulnerability import Vulnerability

_FIXTURE_DIRS = ("fixtures/vulnerable_python", "fixtures/vulnerable_javascript")


def resolve_disk_path(vulnerability: Vulnerability) -> Optional[str]:
    """Returns the real filesystem path for a vulnerability's source file, or None if it can't be located."""
    scan = vulnerability.scan
    if scan and scan.repo_path:
        candidate = os.path.join(scan.repo_path, vulnerability.file_path)
        if os.path.exists(candidate):
            return candidate

    if os.path.exists(vulnerability.file_path):
        return vulnerability.file_path

    base_name = os.path.basename(vulnerability.file_path)
    for fixture_dir in _FIXTURE_DIRS:
        candidate = os.path.join(fixture_dir, base_name)
        if os.path.exists(candidate):
            return candidate

    return None


def read_source_for_vulnerability(vulnerability: Vulnerability) -> str:
    """
    Reads the full original source file for a vulnerability. Falls back to the
    stored finding snippet (a single line/call, not the whole file) only when the
    real file genuinely cannot be located on disk anymore.
    """
    disk_path = resolve_disk_path(vulnerability)
    if disk_path:
        with open(disk_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    return vulnerability.source_snippet
