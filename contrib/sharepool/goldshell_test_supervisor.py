#!/usr/bin/env python3
"""Independent, sole-restorer supervisor for an explicitly requested miner test.

Run this program separately from the mining worker. Only this supervisor reads
the bridge configuration or changes pools. The worker must publish READY after
its native/profile/listener preflight, then exit successfully only after its own
proof/capture checks pass. No credentials or raw child output go to stdout.
This protects against worker hangs/death, not supervisor death or power loss.
"""
import argparse
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

from goldshell_test_guard import BridgeClient, GuardError, GuardResult, guarded_test

READY = b"sharepool-v7-hardware-ready\n"


@dataclass(frozen=True)
class SupervisedResult(GuardResult):
    worker_cleanup_failed: bool = False


def _ready(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return False
    except OSError:
        raise GuardError("Unsafe worker readiness file") from None
    try:
        status = os.fstat(descriptor)
        if (not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid() or
                stat.S_IMODE(status.st_mode) != 0o600 or status.st_size != len(READY)):
            raise GuardError("Unsafe worker readiness file")
        # Exclusive link publication briefly leaves both staging and final names.
        # It is not ready until the worker removes staging; a retained extra link
        # never authorizes routing and eventually fails the readiness deadline.
        if status.st_nlink != 1:
            return False
        return os.read(descriptor, len(READY) + 1) == READY
    finally:
        os.close(descriptor)


class MiningWorker:
    """Attempt to terminate the owned group and reap its worker leader."""
    def __init__(self, command, log_path):
        self.stopped = False
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=descriptor,
                                            stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            os.close(descriptor)

    def poll(self):
        return self.process.poll()

    def stop(self):
        if self.stopped:
            return
        # The forwarder is in the worker process. This only signals the owned
        # group: signers that create separate sessions need their own cleanup.
        for signum, timeout in ((signal.SIGTERM, 3), (signal.SIGKILL, 3)):
            try:
                os.killpg(self.process.pid, signum)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                continue
            # Also retire remaining members after an already exited group leader.
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.stopped = True
            return
        raise GuardError("Mining worker cleanup did not complete")


def supervise_test(bridge, *, test_pool, backup_path, command, worker_log, ready_path,
                   seconds=90, ready_seconds=30, worker_factory=MiningWorker):
    """Start/preflight a mining child, then own the complete pool test guard.

    The supervisor stays armed through restoration. Readiness is a local worker
    lifecycle handshake, never a claim of native validity or ASIC compatibility.
    The command must be a reviewed mining-only worker with no bridge operations.
    """
    if (not isinstance(command, (tuple, list)) or not command or
            any(type(value) is not str or not value or "\0" in value for value in command) or
            any(type(value) not in (int, float) or not math.isfinite(value) or not 0.1 <= value <= 600
                for value in (seconds, ready_seconds))):
        raise GuardError("Explicit worker command and bounded test intervals required")
    backup_path, worker_log, ready_path = map(Path, (backup_path, worker_log, ready_path))
    if len({path.absolute() for path in (backup_path, worker_log, ready_path)}) != 3:
        raise GuardError("Separate private worker and restoration paths required")
    if any(path.exists() or path.is_symlink() for path in (backup_path, worker_log, ready_path)):
        raise GuardError("Fresh private worker and restoration paths required")
    worker = worker_factory(command, worker_log)
    result, cleanup_failed = None, False
    try:
        deadline = time.monotonic() + ready_seconds
        while not _ready(ready_path):
            if worker.poll() is not None or time.monotonic() >= deadline:
                raise GuardError("Mining worker failed bounded preflight")
            time.sleep(0.02)
        if worker.poll() is not None:
            raise GuardError("Mining worker exited before temporary routing")

        def run():
            deadline = time.monotonic() + seconds
            while worker.poll() is None:
                if time.monotonic() >= deadline:
                    raise GuardError("Mining worker exceeded its test deadline")
                time.sleep(0.02)
            if worker.poll() != 0:
                raise GuardError("Mining worker failed its capture checks")
            return {"worker_exit": 0}

        def before_restore():
            nonlocal cleanup_failed
            try:
                worker.stop()
            except BaseException:
                cleanup_failed = True
                raise

        # This hook always runs before restoration, even if add/reorder fails
        # before the callback starts. There is only one pool mutator/restorer.
        # A cleanup failure must never prevent restoring the miner. The worker
        # has no bridge client, so it cannot compete with this sole restorer.
        result = guarded_test(bridge, test_pool=test_pool, run_test=run,
                              backup_path=backup_path, before_restore=before_restore)
    finally:
        try:
            worker.stop()
        except BaseException:
            # Retain the guard's verified restoration outcome (or an earlier
            # preflight exception), rather than mask it with cleanup failure.
            cleanup_failed = True
    return SupervisedResult(**{**vars(result),
        "failure_stage": result.failure_stage or ("worker_cleanup" if cleanup_failed else "")},
        worker_cleanup_failed=cleanup_failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge-config", required=True)
    parser.add_argument("--test-url", required=True)
    parser.add_argument("--backup", required=True)
    parser.add_argument("--worker-log", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--seconds", type=int, default=90)
    parser.add_argument("worker", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.worker[1:] if args.worker[:1] == ["--"] else args.worker
    try:
        bridge = BridgeClient.from_config(args.bridge_config)
        bridge._timeout = min(5, bridge._timeout)
        result = supervise_test(bridge, test_pool={"url": args.test_url, "user": "sharepool.regtest", "password": "x"},
            backup_path=args.backup, command=command, worker_log=args.worker_log,
            ready_path=args.ready_file, seconds=args.seconds)
        print(json.dumps({"ok": result.ok, "restored": result.restored,
                          "failure_stage": result.failure_stage, "restore_failures": result.restore_failures,
                          "worker_cleanup_failed": result.worker_cleanup_failed}))
        return 0 if result.ok else 1
    except BaseException:
        print(json.dumps({"ok": False, "error": "supervised hardware test did not complete"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
