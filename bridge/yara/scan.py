"""YARA scanning bridge for REA.

Scans a binary target against YARA rules and returns structured matches
in REA's evidence format. Invoked as a subprocess by the TypeScript CLI.

Usage: python3 bridge/yara/scan.py <request.json>
Request JSON: {"target_path": "/abs/path", "rules_path": "/abs/path/or/null", "reply_path": "/abs/path"}
"""
import json
import os
import sys
import hashlib
from pathlib import Path

OUTPUT_BYTES = 64 * 1024 * 1024

BUILTIN_RULES = """
rule crypto_aes_sbox {
    meta:
        description = "AES S-Box constant"
        category = "crypto"
    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
    condition:
        $sbox
}

rule crypto_rc4_ksa {
    meta:
        description = "RC4 Key Scheduling Algorithm pattern"
        category = "crypto"
    strings:
        $ksa = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }
    condition:
        $ksa
}

rule suspicious_upx {
    meta:
        description = "UPX packed binary"
        category = "packer"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        2 of ($upx*)
}

rule suspicious_anti_debug {
    meta:
        description = "Anti-debugging techniques"
        category = "evasion"
    strings:
        $ptrace = "ptrace" ascii
        $isdebuggerpresent = "IsDebuggerPresent" ascii
        $ntqueryinformationprocess = "NtQueryInformationProcess" ascii
        $checkremotedebugger = "CheckRemoteDebuggerPresent" ascii
        $outputdebugstring = "OutputDebugString" ascii
    condition:
        2 of them
}

rule suspicious_process_injection {
    meta:
        description = "Process injection API calls"
        category = "injection"
    strings:
        $virtualalloc = "VirtualAllocEx" ascii
        $writeprocessmemory = "WriteProcessMemory" ascii
        $createremotethread = "CreateRemoteThread" ascii
        $ntmapviewofsection = "NtMapViewOfSection" ascii
        $queueuserapc = "QueueUserAPC" ascii
    condition:
        2 of them
}

rule suspicious_keylogger {
    meta:
        description = "Keylogger API patterns"
        category = "spyware"
    strings:
        $getkeystate = "GetAsyncKeyState" ascii
        $getkeyboard = "GetKeyboardState" ascii
        $setwindowshook = "SetWindowsHookEx" ascii
    condition:
        2 of them
}

rule suspicious_network_c2 {
    meta:
        description = "Network C2 indicators"
        category = "c2"
    strings:
        $http_ua = "User-Agent:" ascii
        $http_post = "POST " ascii
        $http_get = "GET " ascii
        $ws_upgrade = "Upgrade: websocket" ascii nocase
        $dns_txt = { 00 10 00 01 }
    condition:
        ($http_ua and ($http_post or $http_get)) or $ws_upgrade or $dns_txt
}

rule suspicious_persistence {
    meta:
        description = "Persistence mechanism indicators"
        category = "persistence"
    strings:
        $run_key = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii nocase
        $schtasks = "schtasks" ascii nocase
        $crontab = "crontab" ascii
        $systemd_service = "[Service]" ascii
        $launchd = "com.apple" ascii
    condition:
        any of them
}

rule suspicious_credential_access {
    meta:
        description = "Credential harvesting indicators"
        category = "credential_access"
    strings:
        $lsass = "lsass.exe" ascii nocase
        $sam = "\\\\SAM" ascii
        $mimikatz = "sekurlsa" ascii nocase
        $shadow = "/etc/shadow" ascii
        $dpapi = "CryptUnprotectData" ascii
    condition:
        any of them
}

rule elf_shellcode_markers {
    meta:
        description = "ELF shellcode execution patterns"
        category = "shellcode"
    strings:
        $syscall = { 0f 05 }
        $int80 = { cd 80 }
        $execve_path = "/bin/sh" ascii
        $execve_path2 = "/bin/bash" ascii
    condition:
        ($syscall or $int80) and ($execve_path or $execve_path2)
}
"""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan(target_path: Path, rules_path: str | None) -> dict:
    import yara

    limitations = []

    if rules_path and Path(rules_path).exists():
        rules = yara.compile(filepath=rules_path)
        rules_source = rules_path
    else:
        rules = yara.compile(source=BUILTIN_RULES)
        rules_source = "builtin-offensive-security-rules"
        limitations.append(
            "Using built-in YARA rules; supply custom rules for deeper analysis."
        )

    matches = rules.match(str(target_path), timeout=60)
    file_hash = sha256_file(target_path)
    file_size = target_path.stat().st_size

    results = []
    categories = set()
    for match in matches:
        meta = match.meta if hasattr(match, "meta") else {}
        category = meta.get("category", "unknown")
        categories.add(category)
        strings_found = []
        for s in match.strings:
            for instance in s.instances:
                strings_found.append(
                    {
                        "identifier": s.identifier,
                        "offset": f"0x{instance.offset:x}",
                        "length": instance.matched_length,
                        "data_preview": instance.matched_data[:32].hex()
                        if instance.matched_data
                        else None,
                    }
                )
        results.append(
            {
                "rule": match.rule,
                "category": category,
                "description": meta.get("description", ""),
                "tags": list(match.tags) if hasattr(match, "tags") else [],
                "strings": strings_found[:50],
                "string_count": len(strings_found),
            }
        )

    return {
        "target": {
            "path": str(target_path),
            "sha256": file_hash,
            "size_bytes": file_size,
        },
        "rules_source": rules_source,
        "match_count": len(results),
        "categories": sorted(categories),
        "matches": results,
        "limitations": limitations,
    }


def main():
    request_path = sys.argv[1]
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))

    target_path = Path(request["target_path"])
    rules_path = request.get("rules_path")
    reply_path = request["reply_path"]

    try:
        if not target_path.exists():
            raise FileNotFoundError(f"Target not found: {target_path}")

        value = scan(target_path, rules_path)
        reply = {"ok": True, "value": value}
    except ImportError:
        reply = {
            "ok": False,
            "reason": "missing-dependency",
            "message": "yara-python is not installed. Install with: pip install yara-python",
        }
    except Exception as error:
        reply = {
            "ok": False,
            "reason": "scan-error",
            "message": f"{type(error).__name__}: {error}",
        }

    encoded = json.dumps(reply, ensure_ascii=True, allow_nan=False).encode("utf-8")
    if len(encoded) > OUTPUT_BYTES:
        encoded = json.dumps(
            {
                "ok": False,
                "reason": "output-limit",
                "message": "YARA scan result exceeds the 64 MiB reply budget.",
            }
        ).encode("utf-8")

    descriptor = os.open(reply_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)


if __name__ == "__main__":
    main()
