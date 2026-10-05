#!/usr/bin/env python3
"""Install TunnelGuard locally on Linux/macOS without root or package downloads."""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
FILES = ["tunnelguard.py", "engines.py", "dashboard.html", "config.example.json",
         "config.multilayer.example.json", "config.managed.example.json",
         "README.md", "README.fa.md", "MULTILAYER.md", "MULTILAYER.fa.md",
         "deploy.py", "deploy_spoof.py", "DEPLOY.md", "DEPLOY.fa.md", "SPOOF.md", "SPOOF.fa.md",
         "diagnostics.py", "maintenance.py", "pair_maintenance.py", "field_test.py", "OPERATIONS.md", "OPERATIONS.fa.md"]


def atomic_copy(source, target):
    if source.resolve() == target.resolve():
        return
    fd, temporary = tempfile.mkstemp(prefix=".tg-install-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(source.read_bytes())
        os.chmod(temporary, 0o644)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".local/share/tunnelguard")
    parser.add_argument("--bin-dir", type=Path, default=Path.home() / ".local/bin")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("On Windows, run python tunnelguard.py directly from the extracted folder.")
    if sys.version_info < (3, 11):
        parser.error("Python 3.11 or newer is required.")
    for name in FILES:
        if not (ROOT / name).is_file():
            parser.error("Incomplete package: " + name)
    prefix, bindir = args.prefix.expanduser().resolve(), args.bin_dir.expanduser().resolve()
    prefix.mkdir(parents=True, exist_ok=True)
    bindir.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        atomic_copy(ROOT / name, prefix / name)
    recipe_dir = prefix / "recipes"
    recipe_dir.mkdir(exist_ok=True)
    for source in (ROOT / "recipes").iterdir():
        if source.is_file():
            atomic_copy(source, recipe_dir / source.name)
    launcher = bindir / "tunnelguard"
    body = "#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(prefix / "tunnelguard.py")) + ' "$@"\n'
    fd, temporary = tempfile.mkstemp(prefix=".tg-launcher-", dir=bindir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
        os.chmod(temporary, 0o755)
        os.replace(temporary, launcher)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"Installed: {prefix}\nLauncher: {launcher}\nExisting config.json preserved.")
    print("Try: " + shlex.quote(str(launcher)) + " demo")
    if not shutil.which("curl"):
        print("Live mode requires curl 8.4+; the offline demo is available now.")


if __name__ == "__main__":
    main()
