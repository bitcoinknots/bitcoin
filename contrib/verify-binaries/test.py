#!/usr/bin/env python3

import json
import sys
import subprocess
from pathlib import Path


def main():
    """Tests ordered roughly from faster to slower."""
    expect_code(run_verify("", "pub", '0.32'), 4, "Nonexistent version should fail")
    expect_code(run_verify("", "pub", '0.32.awefa.12f9h'), 11, "Malformed version should fail")
    expect_code(run_verify('--min-good-sigs 20', "pub", "29.1.knots20250903"), 9, "--min-good-sigs 20 should fail")

    print("- testing verification (29.1.knots20250903-x86_64-linux-gnu.tar.gz)", flush=True)
    _291knots_x86_64_linux_gnu = run_verify("--json", "pub", "29.1.knots20250903-x86_64-linux-gnu.tar.gz")
    try:
        result = json.loads(_291knots_x86_64_linux_gnu.stdout.decode())
    except Exception:
        print("failed on 29.1.knots20250903-x86_64-linux-gnu.tar.gz --json:")
        print_process_failure(_291knots_x86_64_linux_gnu)
        raise

    expect_code(_291knots_x86_64_linux_gnu, 0, "29.1.knots20250903-x86_64-linux-gnu.tar.gz should succeed")
    v = result['verified_binaries']
    assert result['good_trusted_sigs']
    assert len(v) == 1
    assert v['bitcoin-29.1.knots20250903-x86_64-linux-gnu.tar.gz'] == '3752cf932309cd98734eb20ebb6c7aea4b8a10eb329b3d8d8fbd00098ea674fb'

    print("- testing verification (29.1.knots20250903)", flush=True)
    _291knots = run_verify("--json", "pub", "29.1.knots20250903")
    try:
        result = json.loads(_291knots.stdout.decode())
    except Exception:
        print("failed on 29.1.knots20250903 --json:")
        print_process_failure(_291knots)
        raise

    expect_code(_291knots, 0, "29.1.knots20250903 should succeed")
    v = result['verified_binaries']
    assert result['good_trusted_sigs']
    assert v['bitcoin-29.1.knots20250903-aarch64-linux-gnu.tar.gz'] == '505fe70d71609abc42d1d91c23fb0b4ac0c94bcb6fe6674bb6b936a4708576e9'
    assert v['bitcoin-29.1.knots20250903-x86_64-apple-darwin.tar.gz'] == 'fd7b56abc611a5311dde3157346524ae4f03131df4f72948e1c9ba4d10d6cc33'
    assert v['bitcoin-29.1.knots20250903-x86_64-linux-gnu.tar.gz'] == '3752cf932309cd98734eb20ebb6c7aea4b8a10eb329b3d8d8fbd00098ea674fb'


def run_verify(global_args: str, command: str, command_args: str) -> subprocess.CompletedProcess:
    maybe_here = Path.cwd() / 'verify.py'
    path = maybe_here if maybe_here.exists() else Path.cwd() / 'contrib' / 'verify-binaries' / 'verify.py'

    if command == "pub":
        command += " --cleanup"

    return subprocess.run(
        f"{path} {global_args} {command} {command_args}",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)


def expect_code(completed: subprocess.CompletedProcess, expected_code: int, msg: str):
    if completed.returncode != expected_code:
        print(f"{msg!r} failed: got code {completed.returncode}, expected {expected_code}")
        print_process_failure(completed)
        sys.exit(1)
    else:
        print(f"✓ {msg!r} passed")


def print_process_failure(completed: subprocess.CompletedProcess):
    print(f"stdout:\n{completed.stdout.decode()}")
    print(f"stderr:\n{completed.stderr.decode()}")


if __name__ == '__main__':
    main()
