"""capa capabilities detection bridge for REA.

Runs flare-capa against a binary to detect ATT&CK techniques, malware
behaviors, and capabilities. Invoked as a subprocess by the TypeScript CLI.

Usage: python3 bridge/capa/scan.py <request.json>
Request JSON: {"target_path": "/abs/path", "reply_path": "/abs/path", "format": "default|verbose"}
"""
import json
import os
import subprocess
import sys
import hashlib
from pathlib import Path

OUTPUT_BYTES = 64 * 1024 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_capa() -> str | None:
    for candidate in ["capa", "flare-capa"]:
        try:
            result = subprocess.run(
                [candidate, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def scan(target_path: Path, output_format: str) -> dict:
    capa_bin = find_capa()
    if capa_bin is None:
        return {
            "ok": False,
            "reason": "missing-dependency",
            "message": "capa (flare-capa) is not installed. Install with: pip install flare-capa",
        }

    version_result = subprocess.run(
        [capa_bin, "--version"], capture_output=True, text=True, timeout=10
    )
    capa_version = version_result.stdout.strip() if version_result.returncode == 0 else "unknown"

    rules_dir = Path(__file__).parent / "rules"
    cmd = [capa_bin, "--json"]
    if rules_dir.is_dir() and any(rules_dir.glob("**/*.yml")):
        cmd.extend(["-r", str(rules_dir)])
    cmd.append(str(target_path))

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "reason": "timeout",
            "message": "capa analysis timed out after 300 seconds.",
        }

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "unsupported file type" in stderr.lower():
            return {
                "ok": False,
                "reason": "unsupported-format",
                "message": f"capa does not support this file format: {stderr}",
            }
        return {
            "ok": False,
            "reason": "analysis-error",
            "message": f"capa exited with code {result.returncode}: {stderr[:500]}",
        }

    try:
        capa_output = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "reason": "parse-error",
            "message": "Failed to parse capa JSON output.",
        }

    file_hash = sha256_file(target_path)
    file_size = target_path.stat().st_size

    rules = capa_output.get("rules", {})
    if isinstance(rules, list):
        rules = {r.get("meta", {}).get("name", f"rule_{i}"): r for i, r in enumerate(rules)}

    attack_techniques = []
    mbc_behaviors = []
    capabilities = []
    namespaces = set()

    for rule_name, rule_data in rules.items():
        meta = rule_data.get("meta", {})
        namespace = meta.get("namespace", "")
        namespaces.add(namespace.split("/")[0] if namespace else "unknown")

        attack = meta.get("att&ck", meta.get("attack", []))
        if isinstance(attack, list):
            for technique in attack:
                if isinstance(technique, dict):
                    attack_techniques.append(
                        {
                            "technique": technique.get("id", technique.get("technique_id", "")),
                            "name": technique.get("technique", technique.get("name", "")),
                            "tactic": technique.get("tactic", ""),
                            "subtechnique": technique.get("subtechnique", ""),
                        }
                    )
                elif isinstance(technique, str):
                    attack_techniques.append({"technique": technique, "name": rule_name})

        mbc = meta.get("mbc", [])
        if isinstance(mbc, list):
            for behavior in mbc:
                if isinstance(behavior, dict):
                    mbc_behaviors.append(
                        {
                            "id": behavior.get("id", ""),
                            "objective": behavior.get("objective", ""),
                            "behavior": behavior.get("behavior", ""),
                        }
                    )
                elif isinstance(behavior, str):
                    mbc_behaviors.append({"behavior": behavior})

        scopes = meta.get("scopes", {})
        scope_str = "unknown"
        if isinstance(scopes, dict):
            scope_str = scopes.get("static", scopes.get("dynamic", "unknown"))
        elif isinstance(scopes, str):
            scope_str = scopes

        cur_attack = attack if isinstance(attack, list) else []
        cur_mbc = mbc if isinstance(mbc, list) else []

        capabilities.append(
            {
                "name": rule_name,
                "namespace": namespace,
                "scope": scope_str,
                "attack": [t.get("technique", t.get("name", "")) for t in attack_techniques[-len(cur_attack):]] if cur_attack else [],
                "mbc": [b.get("behavior", b.get("id", "")) for b in mbc_behaviors[-len(cur_mbc):]] if cur_mbc else [],
                "lib": meta.get("lib", False),
            }
        )

    unique_techniques = {}
    for t in attack_techniques:
        tid = t.get("technique", "")
        if tid and tid not in unique_techniques:
            unique_techniques[tid] = t

    unique_mbc = {}
    for b in mbc_behaviors:
        bid = b.get("id", b.get("behavior", ""))
        if bid and bid not in unique_mbc:
            unique_mbc[bid] = b

    summary = {
        "total_capabilities": len(capabilities),
        "attack_techniques_count": len(unique_techniques),
        "mbc_behaviors_count": len(unique_mbc),
        "namespaces": sorted(namespaces),
        "lib_rules": sum(1 for c in capabilities if c.get("lib")),
    }

    limitations = [
        "capa analysis is static; runtime behavior may differ.",
        "Rule matches indicate capability presence, not confirmed execution.",
    ]

    return {
        "ok": True,
        "value": {
            "target": {
                "path": str(target_path),
                "sha256": file_hash,
                "size_bytes": file_size,
            },
            "provider": {"name": "capa", "version": capa_version},
            "summary": summary,
            "attack_techniques": list(unique_techniques.values()),
            "mbc_behaviors": list(unique_mbc.values()),
            "capabilities": capabilities if output_format == "verbose" else capabilities[:50],
            "limitations": limitations,
        },
    }


def main():
    request_path = sys.argv[1]
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))

    target_path = Path(request["target_path"])
    reply_path = request["reply_path"]
    output_format = request.get("format", "default")

    try:
        if not target_path.exists():
            result = {
                "ok": False,
                "reason": "not-found",
                "message": f"Target not found: {target_path}",
            }
        else:
            result = scan(target_path, output_format)
    except Exception as error:
        result = {
            "ok": False,
            "reason": "bridge-error",
            "message": f"{type(error).__name__}: {error}",
        }

    encoded = json.dumps(result, ensure_ascii=True, allow_nan=False).encode("utf-8")
    if len(encoded) > OUTPUT_BYTES:
        encoded = json.dumps(
            {
                "ok": False,
                "reason": "output-limit",
                "message": "capa result exceeds the 64 MiB reply budget.",
            }
        ).encode("utf-8")

    descriptor = os.open(reply_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)


if __name__ == "__main__":
    main()
