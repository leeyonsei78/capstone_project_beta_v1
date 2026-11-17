"""Collect setup diagnostics; never install software or run AI experiments."""

import argparse
import datetime as dt
import json
import locale
from pathlib import Path
import subprocess


def decode(data):
    if b"\x00" in data or data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16" if data[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-16-le", errors="replace").strip()
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return data.decode(locale.getpreferredencoding(False), errors="replace").strip()


def probe(command):
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=30, check=False)
        return {"command": command, "exit_code": result.returncode,
                "stdout": decode(result.stdout), "stderr": decode(result.stderr)}
    except subprocess.TimeoutExpired as exc:
        return {"command": command, "error": "timeout after 30 seconds",
                "stdout": decode(exc.stdout or b""), "stderr": decode(exc.stderr or b"")}
    except OSError as exc:
        return {"command": command, "error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distro", default="Ubuntu-24.04")
    args = parser.parse_args()
    checks = {}

    def record(name, command):
        result = probe(command)
        checks[name] = result
        print(f"[{name}]", flush=True)
        print(result.get("stdout") or result.get("stderr") or result.get("error") or "(no output)", flush=True)
        return result

    distros = record("wsl_distributions", ["wsl.exe", "--list", "--quiet"])
    if distros.get("exit_code") == 0:
        record("wsl_versions", ["wsl.exe", "--list", "--verbose"])
        if args.distro in distros.get("stdout", "").splitlines():
            # Invoking this check may start the selected WSL distribution.
            record("linux_kvm", ["wsl.exe", "-d", args.distro, "--", "sh", "-c", """
uname -m
uname -r
id
if [ ! -c /dev/kvm ]; then
    echo KVM_DEVICE_MISSING
    exit 2
fi
ls -l /dev/kvm
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    echo KVM_READ_WRITE_OK_BOOT_NOT_TESTED
else
    echo KVM_PERMISSION_DENIED
    exit 3
fi
"""])
        else:
            checks["linux_kvm"] = {"skipped": f"{args.distro} not listed"}
    else:
        checks["linux_kvm"] = {"skipped": "WSL enumeration failed; installation state unknown"}
    record("docker", ["docker", "version"])
    record("compose", ["docker", "compose", "version"])
    record("gpu", ["nvidia-smi", "--query-gpu=name,memory.used,memory.total,utilization.gpu", "--format=csv"])
    record("ollama_loaded_models", ["ollama", "ps"])

    now = dt.datetime.now(dt.timezone.utc)
    output_dir = Path(__file__).resolve().parents[1] / "research" / "environment"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"preflight-{now.strftime('%Y%m%dT%H%M%S%fZ')}.json"
    output.write_text(json.dumps({"recorded_at": now.isoformat(), "checks": checks,
                                 "note": "Diagnostics only; no Docker smoke test, microVM boot, or AI experiment performed."},
                                ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Saved: {output}")


if __name__ == "__main__":
    main()
