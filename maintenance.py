"""Transactional lifecycle management for standard TunnelGuard deployments."""
import argparse
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

import deploy

ROOT = Path(__file__).resolve().parent
STATE = Path("/var/lib/tunnelguard-maintenance")
UNITS = Path("/etc/systemd/system")
TARGETS = {
    "server": (Path("/opt/tunnelguard-node/server"), ["server"]),
    "client": (Path("/opt/tunnelguard-node/client"), [*deploy.KINDS, "guard"]),
    "spoof-server": (Path("/opt/tunnelguard-spoof/server"), ["overlay", "carrier"]),
    "spoof-client": (Path("/opt/tunnelguard-spoof/client"), ["overlay", "carrier", "guard"]),
}


def run(*args):
    return subprocess.run(list(args), check=True, capture_output=True, timeout=60)


def atomic(path, data, mode=0o600):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=".tg-maint-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def private_json(path, value):
    atomic(path, json.dumps(value, indent=2))


def checked_tree(path):
    if path.is_symlink() or any(p.is_symlink() for p in path.rglob("*")):
        raise ValueError("Symlink in managed tree")


def unit_names(target):
    _, names = TARGETS[target]
    return [f"tunnelguard-{target}-{n}.service" for n in names if (UNITS/f"tunnelguard-{target}-{n}.service").is_file()]


@contextlib.contextmanager
def locked():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Linux root required")
    STATE.mkdir(mode=0o700, exist_ok=True)
    STATE.chmod(0o700)
    import fcntl
    with (STATE/"lock").open("a") as f:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def tree_digest(folder):
    h = hashlib.sha256()
    for path in sorted(folder.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            h.update(str(path.relative_to(folder)).encode())
            h.update(path.read_bytes())
    return h.hexdigest()


def snapshot(target):
    prefix, _ = TARGETS[target]
    if not prefix.is_dir():
        raise ValueError("Target not installed")
    checked_tree(prefix)
    identity = uuid.uuid4().hex
    folder = STATE/identity
    folder.mkdir(mode=0o700)
    shutil.copytree(prefix, folder/"tree")
    (folder/"units").mkdir()
    units = unit_names(target)
    active, enabled = [], []
    for unit in units:
        path = UNITS/unit
        if path.is_symlink() or str(prefix) not in path.read_text():
            raise ValueError("Unexpected managed unit")
        shutil.copy2(path, folder/"units"/unit)
        if subprocess.run(["systemctl", "is-active", "--quiet", unit], capture_output=True).returncode == 0:
            active.append(unit)
        if subprocess.run(["systemctl", "is-enabled", "--quiet", unit], capture_output=True).returncode == 0:
            enabled.append(unit)
    meta = dict(target=target, units=units, active=active, enabled=enabled, created=int(time.time()), digest=tree_digest(folder/"tree"))
    deploy.write_private(folder/"meta.json", meta)
    return identity


def read_snapshot(identity, target):
    if not re.fullmatch(r"[a-f0-9]{32}", identity):
        raise ValueError("Invalid snapshot ID")
    folder = STATE/identity
    checked_tree(folder)
    meta = json.loads((folder/"meta.json").read_text())
    if meta["target"] != target or meta["digest"] != tree_digest(folder/"tree"):
        raise ValueError("Snapshot mismatch")
    return folder, meta


def restart(units):
    for unit in units:
        run("systemctl", "restart", unit)
    time.sleep(2)
    for unit in units:
        run("systemctl", "is-active", "--quiet", unit)


def restore(identity, target):
    folder, meta = read_snapshot(identity, target)
    prefix, _ = TARGETS[target]
    # Only fixed registry paths may be removed; snapshots never supply a destination.
    checked_tree(prefix)
    for unit in set(unit_names(target)) | set(meta["units"]):
        subprocess.run(["systemctl", "disable", "--now", unit], capture_output=True)
    if prefix.exists():
        shutil.rmtree(prefix)
    shutil.copytree(folder/"tree", prefix)
    for unit in meta["units"]:
        shutil.copy2(folder/"units"/unit, UNITS/unit)
    run("systemctl", "daemon-reload")
    for unit in meta["enabled"]:
        run("systemctl", "enable", unit)
    restart(meta["active"])


def validate_candidate(prefix, changes):
    with tempfile.TemporaryDirectory(dir=STATE) as tmp:
        folder = Path(tmp)
        for name, data in changes.items():
            if name.endswith(".json") and name not in ("config.json", "guard-backup.json"):
                cfg = json.loads(data)
                if "inbounds" in cfg or "outbounds" in cfg:
                    path = folder/Path(name).name
                    path.write_bytes(data)
                    binary = prefix/"sing-box"
                    run(str(binary), "check", "-c", str(path))
            if name == "config.json":
                from tunnelguard import load_config
                path = folder/"config.json"
                path.write_bytes(data)
                load_config(path)


def transaction(target, changes):
    prefix, _ = TARGETS[target]
    pending = STATE/f"pending-{target}.json"
    if pending.exists():
        raise ValueError("Interrupted operation exists; run recover first")
    checked_tree(prefix)
    validate_candidate(prefix, changes)
    identity = snapshot(target)
    deploy.write_private(pending, {"target": target, "snapshot": identity})
    try:
        for relative, data in changes.items():
            path = prefix/relative
            if path.resolve().parent != prefix.resolve() and path.resolve().parent != (prefix/"app").resolve():
                raise ValueError("Invalid managed file")
            mode = 0o755 if relative in ("sing-box", "spoof") else 0o644 if relative.startswith("app/") else 0o600
            atomic(path, data, mode)
        restart(unit_names(target))
    except BaseException:
        restore(identity, target)
        pending.unlink()
        raise
    pending.unlink()
    return identity


def upgrade(target, cores=False):
    prefix, _ = TARGETS[target]
    changes = {}
    if (prefix/"app").exists():
        for name in ("tunnelguard.py", "engines.py", "dashboard.html"):
            changes[f"app/{name}"] = (ROOT/name).read_bytes()
        # Syntax-check source before touching the running copy.
        for name, data in changes.items():
            if name.endswith(".py"):
                compile(data, name, "exec")
    if cores:
        with tempfile.TemporaryDirectory(dir=STATE) as tmp:
            stage = Path(tmp)
            changes["sing-box"] = deploy.install_core(stage).read_bytes()
            for path in prefix.glob("*.json"):
                cfg = json.loads(path.read_text())
                if "inbounds" in cfg or "outbounds" in cfg:
                    run(str(stage/"sing-box"), "check", "-c", str(path))
            if target.startswith("spoof-"):
                import deploy_spoof
                changes["spoof"] = deploy_spoof.install_binary(stage).read_bytes()
    if not changes:
        raise ValueError("No application on this target; use --cores for verified core replacement")
    return transaction(target, changes)


def remove_spoof_route(cfg):
    cfg = copy.deepcopy(cfg)
    cfg["routes"] = [r for r in cfg["routes"] if r["name"] != "Spoof"]
    if not cfg["routes"]:
        raise ValueError("Cannot detach the only route")
    profiles = cfg.get("profiles", {})
    for name in list(profiles):
        profiles[name] = [r for r in profiles[name] if r != "Spoof"]
        if not profiles[name]:
            del profiles[name]
    if cfg.get("default_profile") not in profiles:
        if not profiles:
            profiles["All"] = [r["name"] for r in cfg["routes"]]
        cfg["default_profile"] = next(iter(profiles))
    return cfg


def uninstall(target):
    prefix, _ = TARGETS[target]
    if target == "client" and TARGETS["spoof-client"][0].exists() and not (TARGETS["spoof-client"][0]/"app").exists():
        raise ValueError("Remove attached spoof-client first")
    identity = snapshot(target)
    detach = None
    try:
        if target == "spoof-client" and (prefix/"guard-backup.json").exists():
            config = TARGETS["client"][0]/"config.json"
            if config.exists():
                cfg = remove_spoof_route(json.loads(config.read_text()))
                detach = transaction("client", {"config.json": json.dumps(cfg).encode()})
        for unit in unit_names(target):
            run("systemctl", "disable", "--now", unit)
            (UNITS/unit).unlink()
        run("systemctl", "daemon-reload")
        shutil.rmtree(prefix)
    except BaseException:
        restore(identity, target)
        if detach:
            restore(detach, "client")
        raise
    # Kept outside removed tree so uninstall is recoverable.
    if detach:
        deploy.write_private(STATE/identity/"detached.json", {"client_snapshot": detach})
    return identity


def prepare_rotation(target, address):
    if target not in ("server", "spoof-server"):
        raise ValueError("Prepare on a server target")
    prefix, _ = TARGETS[target]
    name = "server.json" if target == "server" else "overlay.json"
    old = json.loads((prefix/name).read_text())
    expected = set(deploy.KINDS) if target == "server" else {"hysteria2"}
    if {i["type"] for i in old["inbounds"]} != expected or len(old["inbounds"]) != len(expected):
        raise ValueError("Rotation requires the standard single-pair deployment")
    if any(len(i.get("users", [])) != 1 for i in old["inbounds"] if i["type"] != "shadowsocks"):
        raise ValueError("Multi-user rotation is not supported")
    ports = [next(i["listen_port"] for i in old["inbounds"] if i["type"] == kind) for kind in deploy.KINDS] if target == "server" else [18443, 18444, 18445]
    identity = uuid.uuid4().hex
    folder = STATE/("rotation-"+identity)
    b = deploy.generate_server(folder, address, ports)
    generated = json.loads((folder/"server.json").read_text())
    for inbound in old["inbounds"]:
        fresh = next(i for i in generated["inbounds"] if i["type"] == inbound["type"])
        if inbound["type"] == "shadowsocks":
            inbound["password"] = fresh["password"]
        else:
            inbound["users"] = fresh["users"]
            inbound["tls"].update(certificate=fresh["tls"]["certificate"], key=fresh["tls"]["key"])
    b["rotation"] = dict(id=identity, family="spoof" if target.startswith("spoof") else "base")
    private_json(folder/"pairing.json", b)
    changes = {name: json.dumps(old).encode()}
    validate_candidate(prefix, changes)
    deploy.write_private(folder/"plan.json", dict(target=target, before=tree_digest(prefix), changes={k:v.decode() for k,v in changes.items()}))
    return identity


def rotation_folder(identity):
    if not re.fullmatch(r"[a-f0-9]{32}", identity):
        raise ValueError("Invalid rotation ID")
    return STATE/("rotation-"+identity)


def stage_client(target, bundle):
    deploy.validate_bundle(bundle)
    expected = "spoof" if target == "spoof-client" else "base" if target == "client" else "invalid"
    if bundle["rotation"]["family"] != expected:
        raise ValueError("Rotation target mismatch")
    prefix, _ = TARGETS[target]
    identity = bundle["rotation"]["id"]
    folder = rotation_folder(identity)
    if folder.exists():
        raise ValueError("Rotation already staged")
    names = ["overlay"] if target == "spoof-client" else list(deploy.KINDS)
    changes = {}
    if target == "spoof-client":
        if json.loads((prefix/"carrier.json").read_text())["remote"] != bundle["address"]:
            raise ValueError("Rotation peer mismatch")
    for name in names:
        cfg = json.loads((prefix/f"{name}.json").read_text())
        for out in cfg["outbounds"]:
            if target == "client" and (out["server"] != bundle["address"] or out["server_port"] != bundle["ports"][out["type"]]):
                raise ValueError("Rotation peer mismatch")
            out["password"] = bundle["passwords"][out["type"]]
            if "tls" in out:
                out["tls"]["certificate"] = bundle["certificate"].splitlines()
        changes[f"{name}.json"] = json.dumps(cfg).encode()
    validate_candidate(prefix, changes)
    folder.mkdir(mode=0o700)
    deploy.write_private(folder/"plan.json", dict(target=target, before=tree_digest(prefix), changes={k:v.decode() for k,v in changes.items()}))
    return identity


def commit_rotation(target, identity):
    folder = rotation_folder(identity)
    plan = json.loads((folder/"plan.json").read_text())
    if plan["target"] != target or tree_digest(TARGETS[target][0]) != plan["before"] or (folder/"committed.json").exists():
        raise ValueError("Rotation target changed or already committed")
    backup = transaction(target, {k:v.encode() for k,v in plan["changes"].items()})
    deploy.write_private(folder/"committed.json", {"snapshot": backup})
    return backup


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=["upgrade", "rollback", "uninstall", "prepare-rotation", "stage-rotation", "commit-rotation", "rotation-bundle", "abort-rotation", "certificate-status", "snapshots", "recover"])
    p.add_argument("--target", required=True, choices=list(TARGETS))
    p.add_argument("--snapshot")
    p.add_argument("--rotation")
    p.add_argument("--address")
    p.add_argument("--cores", action="store_true")
    p.add_argument("--bundle", type=Path)
    p.add_argument("--bundle-stdin", action="store_true")
    a = p.parse_args()
    try:
        with locked():
            if a.command == "snapshots":
                snapshots = []
                for path in STATE.glob("*/meta.json"):
                    meta = json.loads(path.read_text())
                    if meta["target"] == a.target:
                        snapshots.append(dict(id=path.parent.name, created=meta["created"]))
                result = {"snapshots": snapshots, "interrupted": (STATE/f"pending-{a.target}.json").exists()}
            elif a.command == "recover":
                pending = STATE/f"pending-{a.target}.json"
                record = json.loads(pending.read_text())
                restore(record["snapshot"], a.target)
                pending.unlink()
                result = {"restored": True}
            elif a.command == "certificate-status":
                from diagnostics import certificate_days
                prefix, _ = TARGETS[a.target]
                name = "server.json" if a.target == "server" else "overlay.json" if a.target.startswith("spoof") else "trojan.json"
                result = {"remaining_days": certificate_days(json.loads((prefix/name).read_text()))}
            elif a.command == "upgrade":
                result = {"snapshot": upgrade(a.target, a.cores)}
            elif a.command == "uninstall":
                result = {"snapshot": uninstall(a.target)}
            elif a.command == "rollback":
                restore(a.snapshot or "", a.target)
                detached = STATE/(a.snapshot or "")/"detached.json"
                if detached.exists():
                    restore(json.loads(detached.read_text())["client_snapshot"], "client")
                result = {"restored": True}
            elif a.command == "prepare-rotation":
                result = {"rotation": prepare_rotation(a.target, a.address)}
            elif a.command == "rotation-bundle":
                # Explicit machine-to-machine secret export; coordinator never prints it.
                folder = rotation_folder(a.rotation or "")
                if json.loads((folder/"plan.json").read_text())["target"] != a.target:
                    raise ValueError("Wrong rotation target")
                result = json.loads((folder/"pairing.json").read_text())
            elif a.command == "stage-rotation":
                raw = sys.stdin.buffer.read(32769) if a.bundle_stdin else a.bundle.read_bytes()
                if len(raw) > 32768:
                    raise ValueError("Bundle too large")
                result = {"rotation": stage_client(a.target, json.loads(raw))}
            elif a.command == "commit-rotation":
                result = {"snapshot": commit_rotation(a.target, a.rotation or "")}
            else:
                folder = rotation_folder(a.rotation or "")
                plan = json.loads((folder/"plan.json").read_text())
                if plan["target"] != a.target:
                    raise ValueError("Wrong rotation target")
                committed = folder/"committed.json"
                if committed.exists():
                    restore(json.loads(committed.read_text())["snapshot"], a.target)
                result = {"restored": True}
        print(json.dumps(result))
        return 0
    except (ValueError, KeyError, TypeError, AttributeError, OSError, subprocess.SubprocessError):
        print("عملیات کامل نشد؛ وضعیت سرویس و پشتیبان‌ها را بررسی کنید. / Operation incomplete; inspect services and snapshots.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
