#!/usr/bin/env python3
"""Reversible pool switching through the existing, local Goldshell bridge.

This module does not start a test or contact a miner by itself. A caller must
authorize a test, supply a bounded ``run_test`` callback, and verify the miner's
return to its production pool after this configuration guard finishes. Python
``finally`` is not a watchdog: power loss, SIGKILL, or a disconnected bridge can
prevent restoration. The private, exclusive backup supports manual recovery.
No fan, power, network, restart, or factory-reset operation is exposed here.
"""

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import urllib.error
import urllib.request


class GuardError(RuntimeError):
    """A deliberately credential-free configuration or bridge error."""


@dataclass(frozen=True)
class GuardResult:
    test_completed: bool
    restored: bool
    failure_stage: str
    restore_failures: tuple
    backup_path: Path
    test_result: object = field(default=None, repr=False)

    @property
    def ok(self):
        return self.test_completed and self.restored and not self.failure_stage


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GuardError("Bridge redirects are not allowed")


class BridgeClient:
    """Private-config client; sends credentials only to numeric loopback.

    The environment's HTTP proxies and redirects are disabled. Responses and
    underlying exception strings are never printed or attached to errors.
    """

    ROUTES = frozenset({
        ("GET", "/api/miner/status"),
        ("GET", "/api/miner/pools"),
        ("GET", "/api/miner/settings"),
        ("POST", "/api/miner/pools"),
        ("DELETE", "/api/miner/pools"),
        ("PUT", "/api/miner/pools/order"),
    })
    MAX_RESPONSE_BYTES = 2 * 1024 * 1024

    def __init__(self, *, host, port, token, timeout=15):
        if host == "localhost":
            host = "127.0.0.1"
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise GuardError("Bridge host must be numeric loopback") from None
        if not address.is_loopback:
            raise GuardError("Bridge host must be loopback")
        if type(port) is not int or not 1 <= port <= 65535:
            raise GuardError("Invalid bridge port")
        if not isinstance(token, str) or len(token) < 32 or any(c in token for c in "\r\n"):
            raise GuardError("Invalid bridge authentication configuration")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
            raise GuardError("Bridge timeout must be at most 60 seconds")
        host_text = "[{}]".format(host) if address.version == 6 else host
        self._base_url = "http://{}:{}".format(host_text, port)
        self._token = token
        self._timeout = timeout
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())

    @classmethod
    def from_config(cls, path):
        """Read the bridge's existing config, without creating or changing it."""
        try:
            with open(path, "r", encoding="utf-8") as source:
                config = json.load(source)
            return cls(host=config.get("bridgeHost", "127.0.0.1"),
                       port=config.get("bridgePort", 4317),
                       token=config["apiToken"],
                       timeout=min(60, config.get("requestTimeoutMs", 8000) / 1000 + 5))
        except Exception:
            raise GuardError("Cannot load valid private bridge configuration") from None

    def __call__(self, method, path, body=None):
        if (method, path) not in self.ROUTES:
            raise GuardError("Bridge operation is outside the pool test guard")
        try:
            payload = None if body is None else json.dumps(body).encode("utf-8")
            request = urllib.request.Request(
                self._base_url + path, data=payload, method=method,
                headers={"Authorization": "Bearer " + self._token,
                         "Content-Type": "application/json"})
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
            if len(raw) > self.MAX_RESPONSE_BYTES:
                raise GuardError("Bridge response is too large")
            result = json.loads(raw)
            if not isinstance(result, dict) or result.get("ok") is not True:
                raise GuardError("Bridge request did not succeed")
            return result
        except Exception:
            raise GuardError("Bridge request failed") from None


def _call(bridge, method, path, body=None):
    try:
        result = bridge(method, path, copy.deepcopy(body))
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise GuardError("Bridge operation did not succeed")
        return copy.deepcopy(result)
    except Exception:
        raise GuardError("Bridge operation failed") from None


def _identity(pool):
    if not isinstance(pool, dict):
        raise GuardError("Invalid pool configuration")
    password = pool.get("pass", pool.get("password"))
    if "pass" in pool and "password" in pool and pool["pass"] != pool["password"]:
        raise GuardError("Ambiguous pool password fields")
    result = (pool.get("url"), pool.get("user"), password)
    if any(not isinstance(value, str) for value in result) or not all(result[:2]):
        raise GuardError("Pool credentials are missing from the configuration")
    return result


def _pools(bridge):
    value = _call(bridge, "GET", "/api/miner/pools")["pools"]
    for unused in range(4):
        if isinstance(value, list):
            break
        if not isinstance(value, dict):
            raise GuardError("Invalid pool list response")
        if "data" in value:
            value = value["data"]
        elif "pools" in value:
            value = value["pools"]
        else:
            raise GuardError("Invalid pool list response")
    if not isinstance(value, list) or len(value) > 64:
        raise GuardError("Invalid pool list size")
    identities = [_identity(pool) for pool in value]
    if len(set(identities)) != len(identities):
        raise GuardError("Duplicate pool entries cannot be managed safely")
    return value


def _settings(bridge):
    settings = _call(bridge, "GET", "/api/miner/settings").get("settings")
    if not isinstance(settings, dict):
        raise GuardError("Invalid miner settings response")
    return settings


def _configured_order(pools):
    for index, pool in enumerate(pools):
        if "pool-priority" in pool:
            priority = pool["pool-priority"]
            if type(priority) is not int or priority != index:
                raise GuardError("Pool priority does not match the reported order")
    return [_identity(pool) for pool in pools]


def _ordered(bridge, pools):
    # Preserve complete API entries and update the ordering fields returned by
    # the device. Read-back verification is mandatory after changing priority.
    ordered = copy.deepcopy(pools)
    for index, pool in enumerate(ordered):
        for key in ("dragid", "pool-priority"):
            if key in pool:
                pool[key] = index
    _call(bridge, "PUT", "/api/miner/pools/order", {"pools": ordered})


def _backup(path, pools, settings, test_pool):
    record = {"format": 1, "created_at": datetime.now(timezone.utc).isoformat(),
              "pools": pools, "settings": settings, "test_pool": test_pool}
    try:
        payload = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode("utf-8")
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        raise GuardError("Cannot create and sync a new private miner backup") from None


def _restore(bridge, original, settings, test_identity):
    failures = []
    original_ids = [_identity(pool) for pool in original]
    try:
        current = _pools(bridge)
        by_id = {_identity(pool): pool for pool in current}
        if any(identity not in by_id for identity in original_ids):
            raise GuardError("An original pool disappeared")
        # Preserve unrelated concurrent additions; verification will report
        # that the configuration no longer matches the exclusive snapshot.
        extras = [pool for pool in current if _identity(pool) not in original_ids]
        _ordered(bridge, [by_id[identity] for identity in original_ids] + extras)
    except Exception:
        failures.append("restore_order")
    try:
        current = _pools(bridge)
        for index, pool in enumerate(current):
            if _identity(pool) == test_identity:
                dragid = pool.get("dragid", index)
                if type(dragid) is not int or dragid < 0:
                    raise GuardError("Invalid temporary pool slot")
                _call(bridge, "DELETE", "/api/miner/pools",
                      {"url": test_identity[0], "user": test_identity[1],
                       "password": test_identity[2], "dragid": dragid})
                break
    except Exception:
        failures.append("remove_test_pool")
    try:
        if _configured_order(_pools(bridge)) != original_ids:
            raise GuardError("Restored pool configuration differs")
    except Exception:
        failures.append("verify_pools")
    try:
        if _settings(bridge) != settings:
            raise GuardError("Miner settings changed during the test")
    except Exception:
        failures.append("verify_settings")
    return tuple(failures)


def guarded_test(bridge, *, test_pool, run_test, backup_path):
    """Temporarily prioritize a new test pool and always attempt restoration.

    ``bridge(method, path, body)`` must implement the documented loopback bridge
    routes. ``run_test()`` must enforce its own timeout and is called only after
    the test-first order and original fallback entries have been read back.
    Preparation errors raise credential-free GuardError before any mutation.
    After mutation starts, failures return GuardResult with ``ok=False``.
    ``restored`` proves configuration equality, not a live Lazarus connection.
    """
    test_identity = _identity(test_pool)
    if not callable(run_test):
        raise GuardError("A bounded test callback is required")
    path = Path(backup_path)
    original = _pools(bridge)
    if not original:
        raise GuardError("An existing fallback pool is required")
    original_ids = _configured_order(original)
    if test_identity in original_ids:
        raise GuardError("The temporary test pool already exists")
    settings = _settings(bridge)
    normalized_test = {"url": test_identity[0], "user": test_identity[1],
                       "password": test_identity[2]}
    _backup(path, original, settings, normalized_test)

    stage = "add_test_pool"
    failure = ""
    completed = False
    result = None
    interrupted = None
    try:
        # Enter the protected region BEFORE calling a mutation: a bridge can
        # apply a change and then lose its HTTP response.
        _call(bridge, "POST", "/api/miner/pools", normalized_test)
        stage = "verify_add"
        current = _pools(bridge)
        by_id = {_identity(pool): pool for pool in current}
        if set(by_id) != set(original_ids + [test_identity]):
            raise GuardError("Unexpected pool changes during test setup")
        stage = "prioritize_test_pool"
        _ordered(bridge, [by_id[test_identity]] + [by_id[identity] for identity in original_ids])
        stage = "verify_test_order"
        if _configured_order(_pools(bridge)) != [test_identity] + original_ids:
            raise GuardError("The test pool did not become first with original fallbacks")
        stage = "run_test"
        result = run_test()
        completed = True
    except Exception:
        failure = stage
    except BaseException as exc:
        failure = "interrupted"
        interrupted = exc
    finally:
        restore_failures = _restore(bridge, original, settings, test_identity)
    if interrupted is not None:
        # Never let interrupt output contain callback text or mask restoration
        # failure. The caller can inspect a stable result and terminate itself.
        result = None
    return GuardResult(completed, not restore_failures, failure,
                       restore_failures, path, result)
