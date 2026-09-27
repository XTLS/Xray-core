"""Reproduce the bounded execution RFC checks without changing source files."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PACKAGE_FILES = {
    "docs/rfc/execution/README.md",
    "docs/rfc/execution/OWNERSHIP_MAP.md",
    "docs/rfc/execution/DESIGN_DECISIONS.md",
    "docs/rfc/execution/MIGRATION.md",
    "docs/rfc/execution/VALIDATION.md",
    "docs/rfc/execution/source-manifest.json",
    "testing/executionprobe/overlay.py",
    "testing/executionprobe/validate.py",
    "testing/executionprobe/probe.go",
    "testing/executionprobe/native_guard.go",
}


def run(args, cwd=ROOT, **kwargs):
    print("+ " + " ".join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), cwd=cwd, check=True, **kwargs)


def audit():
    manifest = json.loads((ROOT / "docs/rfc/execution/source-manifest.json").read_text())
    for name, expected in manifest["files"].items():
        data = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError("Public source mismatch: " + name)
    for name, expected in manifest["r2_files"].items():
        data = subprocess.check_output(
            ["git", "show", manifest["r2_source_commit"] + ":" + name], cwd=ROOT
        ).replace(b"\r\n", b"\n")
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError("Original R2 commit mismatch: " + name)
    baseline = manifest["baseline"]
    allowed = set(manifest["files"]) | PACKAGE_FILES
    changed = set(subprocess.check_output(
        ["git", "diff", "--name-only", baseline, "--"], cwd=ROOT, text=True
    ).splitlines())
    changed.update(subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, text=True
    ).splitlines())
    if changed != allowed:
        raise RuntimeError("Export allowlist mismatch: extra=" + str(sorted(changed - allowed))
                           + "; missing=" + str(sorted(allowed - changed)))
    paths = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", baseline], cwd=ROOT, text=True
    ).splitlines()
    for name in paths:
        if name.endswith("_test.go") or "/testdata/" in name or name in ("go.mod", "go.sum"):
            original = subprocess.check_output(["git", "show", baseline + ":" + name], cwd=ROOT)
            current = (ROOT / name).read_bytes()
            if original.replace(b"\r\n", b"\n") != current.replace(b"\r\n", b"\n"):
                raise RuntimeError("Original fixture/test/dependency changed: " + name)
    print("PASS: exact 65-path export; public and original R2 hashes match; original tests, fixtures and dependencies unchanged.")


def focused():
    run(["go", "test", "-race", "-count=1", "-timeout=3m",
         "./transport/exchange", "./features/outbound", "./proxy/socks",
         "./common/mux", "./common/retry", "./proxy/freedom",
         "./proxy/shadowsocks", "./proxy/vless/outbound"])
    run(["go", "test", "-race", "-count=1", "-timeout=3m",
         "./app/proxyman/outbound", "-run", "^Test(Packet|Stream)"])
    run(["go", "test", "-race", "-count=1", "-timeout=3m",
         "./testing/scenarios", "-run", "^TestE1"])


def streams():
    with tempfile.TemporaryDirectory(prefix="xray-execution-probe-") as name:
        output = Path(name)
        run([sys.executable, HERE / "overlay.py", ROOT, output])
        binary = output / ("probe.exe" if os.name == "nt" else "probe")
        run(["go", "build", "-race", "-overlay", output / "candidate-overlay.json",
             "-o", binary, HERE / "probe.go", HERE / "native_guard.go"])
        for scenario in ("socks", "trojan", "ss", "vless"):
            for stats in (False, True):
                command = [binary, "-scenario", scenario, "-n", "1", "-warmup", "1", "-size", "1024"]
                if stats:
                    command.append("-stats")
                if scenario == "trojan":
                    command.extend(["-coalesce", "-sniff", "-zero-buffer"])
                if scenario in ("ss", "vless"):
                    command.append("-greeting")
                result = run(command, capture_output=True, text=True, timeout=90)
                rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
                if len(rows) != 1:
                    raise RuntimeError("Missing probe result: " + result.stdout + result.stderr)
                row = rows[0]
                guard = row.get("native_guard", {})
                if (guard.get("admitted") != 2 or guard.get("handler_returned") != 2
                        or guard.get("legacy") != 0 or not row["native_counters_positive"]):
                    raise RuntimeError("Native path/counter proof failed: " + json.dumps(row))
                # This guarded race run is functional evidence, not a cost sample.
                print(json.dumps({key: row[key] for key in (
                    "scenario", "stats", "server_first", "coalesced", "sniff",
                    "zero_buffer", "native_guard", "native_counters_positive",
                    "trace_counts", "native_timers_remaining_at_payload_end", "boundary")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("audit", "focused", "streams", "compile", "all"))
    args = parser.parse_args()
    checks = {"audit": audit, "focused": focused, "streams": streams,
              "compile": lambda: run(["go", "test", "./...", "-run", "^$"])}
    for check in checks if args.check == "all" else (args.check,):
        checks[check]()


if __name__ == "__main__":
    main()
