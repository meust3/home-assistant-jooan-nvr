"""Prove the custom integration imports without the repository on sys.path."""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPOSITORY_ROOT / "custom_components" / "jooan_nvr"
FORBIDDEN_IMPORTS = {"jooan_discovery", "tests"}


def _validate_imports() -> None:
    """Reject imports from repository-only packages before copying anything."""
    for source_file in SOURCE.rglob("*.py"):
        tree = ast.parse(source_file.read_text(encoding="utf-8"), source_file)
        for node in ast.walk(tree):
            imported: set[str] = set()
            if isinstance(node, ast.Import):
                imported = {alias.name.split(".", 1)[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported = {node.module.split(".", 1)[0]}
            invalid = imported & FORBIDDEN_IMPORTS
            if invalid:
                names = ", ".join(sorted(invalid))
                raise SystemExit(f"{source_file.relative_to(REPOSITORY_ROOT)} imports {names}")


def main() -> None:
    """Copy only the component and import every Python module in isolated mode."""
    _validate_imports()
    with tempfile.TemporaryDirectory(prefix="jooan-integration-isolation-") as directory:
        isolated_root = Path(directory)
        destination = isolated_root / "custom_components" / "jooan_nvr"
        shutil.copytree(SOURCE, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        program = """
import importlib
import pathlib
import sys

isolated_root = pathlib.Path(sys.argv[1]).resolve()
repository_root = pathlib.Path(sys.argv[2]).resolve()
assert repository_root not in (pathlib.Path(item).resolve() for item in sys.path if item)
sys.path.insert(0, str(isolated_root))
component = isolated_root / "custom_components" / "jooan_nvr"
for source_file in sorted(component.rglob("*.py")):
    relative = source_file.relative_to(isolated_root).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    importlib.import_module(".".join(parts))
assert "jooan_discovery" not in sys.modules
print("isolated integration import passed")
"""
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                program,
                str(isolated_root),
                str(REPOSITORY_ROOT),
            ],
            cwd=isolated_root,
            check=True,
        )


if __name__ == "__main__":
    main()
