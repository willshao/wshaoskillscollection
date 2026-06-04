"""Shared pytest config: make `_shared/contract.py` and skill modules importable."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]   # IIS/
SHARED = ROOT / "_shared"

# Make `import contract` and skill modules work.
for p in (SHARED, ROOT, ROOT / "IIS_logs" / "scripts", ROOT / "orchestrator" / "scripts"):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def sample_iis_log(fixtures_dir: Path) -> Path:
    return fixtures_dir / "sample_iis.log"


@pytest.fixture(scope="session")
def project_root() -> Path:
    return ROOT
