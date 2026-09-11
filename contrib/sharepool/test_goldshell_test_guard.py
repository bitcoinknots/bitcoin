#!/usr/bin/env python3
"""No hardware or network is accessed by these restoration tests."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from goldshell_test_guard import BridgeClient, GuardError, guarded_test


ORIGINAL = [
    {"url": "stratum+tcp://lazarus.example:3333", "user": "original-worker",
     "pass": "original-secret", "dragid": 0, "pool-priority": 0,
     "active": True, "legal": True},
    {"url": "stratum+tcp://backup.example:3333", "user": "fallback-worker",
     "pass": "fallback-secret", "dragid": 1, "pool-priority": 1,
     "active": False, "legal": True},
]
TEST_POOL = {"url": "stratum+tcp://test.example:13333", "user": "test-worker",
             "password": "test-secret"}
SETTINGS = {"tempcontrol": False, "select": 0, "manualPowerplan": "73",
            "powerplans": [{"level": 0}], "manual": True, "version": "v1.0"}


def identities(pools):
    return [(pool["url"], pool["user"], pool.get("pass", pool.get("password")))
            for pool in pools]


class FakeBridge:
    def __init__(self):
        self.pools = copy.deepcopy(ORIGINAL)
        self.settings = copy.deepcopy(SETTINGS)
        self.calls = []
        self.fail_before = {}
        self.fail_after = {}
        self.wrapped = False

    @property
    def mutations(self):
        return [call for call in self.calls if call[0] != "GET"]

    def _fail(self, configured, method, path):
        key = (method, path)
        if configured.get(key, 0):
            configured[key] -= 1
            raise RuntimeError("Do not expose original-secret or test-secret")

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        self._fail(self.fail_before, method, path)
        if (method, path) == ("GET", "/api/miner/pools"):
            pools = copy.deepcopy(self.pools)
            if self.wrapped:
                pools = {"ok": True, "data": pools}
            return {"ok": True, "pools": pools}
        if (method, path) == ("GET", "/api/miner/settings"):
            return {"ok": True, "settings": copy.deepcopy(self.settings)}
        if (method, path) == ("POST", "/api/miner/pools"):
            index = len(self.pools)
            self.pools.append({"url": body["url"], "user": body["user"],
                               "pass": body["password"], "dragid": index,
                               "pool-priority": index, "active": False})
        elif (method, path) == ("PUT", "/api/miner/pools/order"):
            self.pools = copy.deepcopy(body["pools"])
            for index, pool in enumerate(self.pools):
                if pool["pool-priority"] != index or pool["dragid"] != index:
                    raise RuntimeError("Order fields disagree")
                pool["active"] = index == 0
                pool["legal"] = index != 1  # Telemetry may change.
        elif (method, path) == ("DELETE", "/api/miner/pools"):
            expected = (body["url"], body["user"], body["password"])
            index = identities(self.pools).index(expected)
            if self.pools[index]["dragid"] != body["dragid"]:
                raise RuntimeError("Wrong deletion slot")
            del self.pools[index]
        else:
            raise AssertionError("Unexpected bridge mutation")
        self._fail(self.fail_after, method, path)
        return {"ok": True, "result": {}}


class TestGoldshellTestGuard(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backup = Path(self.directory.name) / "private-backup.json"
        self.bridge = FakeBridge()

    def run_guard(self, callback=lambda: "done"):
        return guarded_test(self.bridge, test_pool=TEST_POOL,
                            run_test=callback, backup_path=self.backup)

    def assert_original(self):
        self.assertEqual(identities(self.bridge.pools), identities(ORIGINAL))
        self.assertEqual(self.bridge.settings, SETTINGS)
        deleted = [call[2] for call in self.bridge.calls if call[0] == "DELETE"]
        self.assertTrue(all((item["url"], item["user"], item["password"]) ==
                            (TEST_POOL["url"], TEST_POOL["user"], TEST_POOL["password"])
                            for item in deleted))

    def test_success_keeps_original_fallbacks_then_restores(self):
        def callback():
            self.assertEqual(identities(self.bridge.pools),
                             identities([TEST_POOL] + ORIGINAL))
            self.assertTrue(self.backup.exists())
            return {"accepted_shares": 2}
        result = self.run_guard(callback)
        self.assertTrue(result.ok)
        self.assertEqual(result.test_result, {"accepted_shares": 2})
        self.assert_original()
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o600)
        backup = json.loads(self.backup.read_text())
        self.assertEqual(backup["pools"], ORIGINAL)
        self.assertEqual(backup["settings"], SETTINGS)

    def test_backup_fsync_precedes_first_mutation(self):
        events = []
        actual_fsync = os.fsync
        def fsync(descriptor):
            events.append("fsync")
            return actual_fsync(descriptor)
        def bridge(method, path, body=None):
            if method != "GET":
                events.append("mutate")
            return self.bridge(method, path, body)
        with patch("goldshell_test_guard.os.fsync", fsync):
            result = guarded_test(bridge, test_pool=TEST_POOL, run_test=lambda: None,
                                  backup_path=self.backup)
        self.assertTrue(result.ok)
        self.assertEqual(events[:3], ["fsync", "fsync", "mutate"])

    def test_existing_backup_is_never_overwritten(self):
        self.backup.write_text("preserve existing file")
        with self.assertRaises(GuardError):
            self.run_guard()
        self.assertEqual(self.backup.read_text(), "preserve existing file")
        self.assertEqual(self.bridge.mutations, [])

    def test_symlink_backup_is_never_followed(self):
        target = Path(self.directory.name) / "target"
        target.write_text("keep")
        self.backup.symlink_to(target)
        with self.assertRaises(GuardError):
            self.run_guard()
        self.assertEqual(target.read_text(), "keep")
        self.assertEqual(self.bridge.mutations, [])

    def test_existing_exact_test_pool_is_not_owned(self):
        self.bridge.pools.append(copy.deepcopy(TEST_POOL))
        with self.assertRaises(GuardError):
            self.run_guard()
        self.assertEqual(self.bridge.mutations, [])
        self.assertFalse(self.backup.exists())

    def test_distinct_worker_on_same_url_is_preserved(self):
        self.bridge.pools[0]["url"] = TEST_POOL["url"]
        original = identities(self.bridge.pools)
        result = self.run_guard()
        self.assertTrue(result.ok)
        self.assertEqual(identities(self.bridge.pools), original)

    def test_missing_original_password_refuses_mutation(self):
        del self.bridge.pools[0]["pass"]
        with self.assertRaises(GuardError):
            self.run_guard()
        self.assertEqual(self.bridge.mutations, [])

    def test_empty_original_pool_list_refuses_mutation(self):
        self.bridge.pools = []
        with self.assertRaises(GuardError):
            self.run_guard()
        self.assertEqual(self.bridge.mutations, [])

    def test_nested_pool_response(self):
        self.bridge.wrapped = True
        self.assertTrue(self.run_guard().ok)
        self.assert_original()

    def test_add_failure_before_applying_still_checks_restoration(self):
        self.bridge.fail_before[("POST", "/api/miner/pools")] = 1
        result = self.run_guard(lambda: self.fail("Must not run"))
        self.assertFalse(result.ok)
        self.assertTrue(result.restored)
        self.assertEqual(result.failure_stage, "add_test_pool")
        self.assert_original()

    def test_add_lost_response_after_applying_removes_owned_pool(self):
        self.bridge.fail_after[("POST", "/api/miner/pools")] = 1
        result = self.run_guard(lambda: self.fail("Must not run"))
        self.assertFalse(result.ok)
        self.assertTrue(result.restored)
        self.assert_original()

    def test_reorder_failure_restores_and_does_not_run_test(self):
        self.bridge.fail_before[("PUT", "/api/miner/pools/order")] = 1
        result = self.run_guard(lambda: self.fail("Must not run"))
        self.assertEqual(result.failure_stage, "prioritize_test_pool")
        self.assertTrue(result.restored)
        self.assert_original()

    def test_reorder_lost_response_still_restores(self):
        self.bridge.fail_after[("PUT", "/api/miner/pools/order")] = 1
        result = self.run_guard()
        self.assertTrue(result.restored)
        self.assertFalse(result.test_completed)
        self.assert_original()

    def test_restore_hook_runs_before_cleanup_when_test_never_started(self):
        for failure_point in (("POST", "/api/miner/pools"),
                              ("PUT", "/api/miner/pools/order")):
            with self.subTest(failure_point=failure_point):
                bridge = FakeBridge()
                bridge.fail_after[failure_point] = 1
                restoring = [False]
                hooks = []
                original_call = bridge.__call__
                failed = [False]
                def dispatch(method, path, body=None):
                    if failed[0]:
                        self.assertTrue(restoring[0], "restore began before watchdog transition")
                    try:
                        return original_call(method, path, body)
                    except RuntimeError:
                        failed[0] = True
                        raise
                def before_restore():
                    restoring[0] = True
                    hooks.append("disarmed")
                result = guarded_test(dispatch, test_pool=TEST_POOL,
                    run_test=lambda: self.fail("Test callback must not start"),
                    before_restore=before_restore,
                    backup_path=Path(self.directory.name) / (failure_point[0] + "-backup.json"))
                self.assertEqual(hooks, ["disarmed"])
                self.assertTrue(result.restored)
                self.assertFalse(result.ok)
                self.assertEqual(identities(bridge.pools), identities(ORIGINAL))

    def test_failed_restore_hook_never_prevents_pool_restoration(self):
        def before_restore():
            raise RuntimeError("test-secret")
        result = guarded_test(self.bridge, test_pool=TEST_POOL, run_test=lambda: None,
                              before_restore=before_restore, backup_path=self.backup)
        self.assertTrue(result.restored)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure_stage, "before_restore")
        self.assertNotIn("test-secret", repr(result))
        self.assert_original()

    def test_invalid_restore_hook_refuses_before_mutation(self):
        with self.assertRaises(GuardError):
            guarded_test(self.bridge, test_pool=TEST_POOL, run_test=lambda: None,
                         before_restore=True, backup_path=self.backup)
        self.assertEqual(self.bridge.mutations, [])

    def test_ignored_priority_fields_prevent_running_test(self):
        original_bridge = self.bridge
        reorder_count = [0]
        def bridge(method, path, body=None):
            result = original_bridge(method, path, body)
            if (method, path) == ("PUT", "/api/miner/pools/order"):
                reorder_count[0] += 1
                if reorder_count[0] == 1:
                    original_bridge.pools[0]["pool-priority"] = 2
            return result
        result = guarded_test(bridge, test_pool=TEST_POOL,
                              run_test=lambda: self.fail("Must not run"),
                              backup_path=self.backup)
        self.assertEqual(result.failure_stage, "verify_test_order")
        self.assertTrue(result.restored)
        self.assert_original()

    def test_ambiguous_original_priorities_refuse_mutation(self):
        self.bridge.pools[1]["pool-priority"] = 0
        with self.assertRaises(GuardError):
            self.run_guard()
        self.assertEqual(self.bridge.mutations, [])

    def test_timeout_restores_without_exposing_error(self):
        def timeout():
            raise TimeoutError("original-secret test-secret")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = self.run_guard(timeout)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(result.failure_stage, "run_test")
        self.assertNotIn("secret", repr(result))
        self.assertTrue(result.restored)
        self.assert_original()

    def test_keyboard_interrupt_restores_and_reports_failure(self):
        def interrupt():
            raise KeyboardInterrupt("test-secret")
        result = self.run_guard(interrupt)
        self.assertEqual(result.failure_stage, "interrupted")
        self.assertTrue(result.restored)
        self.assertFalse(result.ok)
        self.assert_original()

    def test_delete_failure_cannot_report_success(self):
        def test():
            self.bridge.fail_before[("DELETE", "/api/miner/pools")] = 1
        result = self.run_guard(test)
        self.assertTrue(result.test_completed)
        self.assertFalse(result.restored)
        self.assertFalse(result.ok)
        self.assertIn("remove_test_pool", result.restore_failures)
        self.assertIn("verify_pools", result.restore_failures)
        self.assertTrue(self.backup.exists())

    def test_restoration_reorder_failure_still_removes_test_pool(self):
        def test():
            self.bridge.fail_before[("PUT", "/api/miner/pools/order")] = 1
        result = self.run_guard(test)
        self.assertFalse(result.restored)
        self.assertIn("restore_order", result.restore_failures)
        self.assert_original()

    def test_changed_settings_are_reported_and_never_written(self):
        def test():
            self.bridge.settings["select"] = 1
        result = self.run_guard(test)
        self.assertFalse(result.restored)
        self.assertIn("verify_settings", result.restore_failures)
        self.assertTrue(all(path.startswith("/api/miner/pools")
                            for method, path, unused in self.bridge.mutations))

    def test_concurrent_pool_is_retained_and_reported(self):
        concurrent = {"url": "stratum+tcp://concurrent.example:3333", "user": "other",
                      "pass": "other-secret", "dragid": 3, "pool-priority": 3}
        def test():
            self.bridge.pools.append(copy.deepcopy(concurrent))
        result = self.run_guard(test)
        self.assertFalse(result.restored)
        self.assertEqual(identities(self.bridge.pools), identities(ORIGINAL + [concurrent]))
        self.assertEqual(len([call for call in self.bridge.calls if call[0] == "DELETE"]), 1)

    def test_ambiguous_duplicate_is_not_deleted(self):
        def test():
            self.bridge.pools.append(copy.deepcopy(self.bridge.pools[0]))
        result = self.run_guard(test)
        self.assertFalse(result.restored)
        self.assertEqual([call for call in self.bridge.calls if call[0] == "DELETE"], [])


class TestPrivateBridgeClient(unittest.TestCase):
    def client(self, **changes):
        args = {"host": "127.0.0.1", "port": 4317, "token": "s" * 64}
        args.update(changes)
        return BridgeClient(**args)

    def test_non_loopback_and_unbounded_timeouts_refused(self):
        for args in ({"host": "10.20.30.40"}, {"host": "miner.local"},
                     {"timeout": 90}, {"timeout": float("nan")}, {"port": True}):
            with self.subTest(args=args), self.assertRaises(GuardError):
                self.client(**args)

    def test_only_explicit_pool_mutations_allowed(self):
        client = self.client()
        for path in ("/api/miner/settings", "/api/miner/restart", "/api/miner/fans",
                     "/api/miner/read?command=reset", "http://example.com"):
            with self.subTest(path=path), self.assertRaises(GuardError):
                client("PUT", path, {})

    def test_http_failure_is_sanitized(self):
        client = self.client()
        with patch.object(client._opener, "open", side_effect=RuntimeError("s" * 64)):
            with self.assertRaises(GuardError) as raised:
                client("GET", "/api/miner/pools")
        self.assertNotIn("s" * 64, str(raised.exception))

    def test_private_config_read_and_invalid_config_error(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"apiToken": "s" * 64, "bridgeHost": "localhost",
                                          "bridgePort": 4317}))
            client = BridgeClient.from_config(config)
            self.assertEqual(client._base_url, "http://127.0.0.1:4317")
            config.write_text(json.dumps({"apiToken": "secret"}))
            with self.assertRaises(GuardError) as raised:
                BridgeClient.from_config(config)
            self.assertNotIn("secret", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
