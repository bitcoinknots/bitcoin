#!/usr/bin/env python3
"""Local admission pressure never suppresses an exact native block candidate."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hash_admission_budget import AdmissionDecision, AdmissionRefused
from hash_stratum import HashStratumService, VardiffStratumService, _Request
from hash_vardiff import VardiffController


def decision(mode="DRAIN"):
    return AdmissionDecision(mode, False, True,
        ("resource-budget",) if mode == "DRAIN" else (),
        ("snapshot_bytes",) if mode == "DRAIN" else (),
        3, "aa" * 32, 1, 4, 1, 1)


class StratumPressureTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.params = ["sharepool.regtest", "old-job", "00" * 8, "00" * 8, "00" * 8]

    def service(self, version, *, native_bits=0x207fffff):
        gate = SimpleNamespace(profile_version=version, mode="test", rules=1, activation_height=1,
            share_work_bits=4, receive=Mock(return_value=True), rpc=Mock(return_value=None),
            set_share_work_bits=Mock(), admission_status=Mock(return_value=decision("OPEN")))
        options = {"sign_owner": lambda unused: None, "observer_rpc": lambda unused: None,
                   "clock": lambda: self.now}
        if version == 8:
            controller = VardiffController(initial_work_bits=4, target_share_seconds=1, clock=lambda: self.now)
            service = VardiffStratumService(gate, controller=controller, **options)
            controller.start()
        else:
            service = HashStratumService(gate, **options)
        self.addCleanup(service.close)
        service.jobs["old-job"] = SimpleNamespace(
            template=SimpleNamespace(header=SimpleNamespace(nBits=native_bits)), target=(1 << 256) - 1,
            snapshot=SimpleNamespace(envelope=SimpleNamespace(share_work_bits=4), owner_signature=bytes(64)),
            authorization=SimpleNamespace(block_for_header=Mock(return_value=b"exact-old-block")))
        return service, gate

    def submit(self, service, hash_int=128):
        proof = SimpleNamespace(hash_int=hash_int, header=b"exact-old-header", block=b"exact-old-block")
        with patch("hash_stratum.proof_from_sia", return_value=proof):
            return service._submit(bytes(4), self.params)

    def test_capacity_refused_winner_is_submitted_without_ack_or_estimator_credit(self):
        for version in (7, 8):
            with self.subTest(version=version):
                service, gate = self.service(version)
                refusal = AdmissionRefused(decision())
                gate.receive.side_effect = refusal
                with self.assertRaises(AdmissionRefused) as caught:
                    self.submit(service)
                self.assertIs(caught.exception, refusal)
                gate.rpc.assert_called_once_with("submitblock", b"exact-old-block".hex())
                gate.receive.assert_called_once()
                self.assertEqual(service.stats["submitted_candidates"], 1)
                self.assertEqual(service.stats["accepted_candidates"], 1)
                self.assertEqual(service.stats["capacity_refused"], 1)
                for name in ("acknowledged", "duplicate", "rejected"):
                    self.assertEqual(service.stats[name], 0)
                if version == 8:
                    self.assertEqual(service.controller.status()["window_accepted_work"], 0)
                    self.assertTrue(service.controller.status()["admission_paused"])

    def test_nonwinning_capacity_refusal_is_not_a_duplicate_or_invalid_share(self):
        for version in (7, 8):
            service, gate = self.service(version, native_bits=0x1d00ffff)
            gate.receive.side_effect = AdmissionRefused(decision())
            with self.assertRaises(AdmissionRefused):
                self.submit(service, 1 << 225)
            gate.rpc.assert_not_called()
            self.assertEqual(service.stats["capacity_refused"], 1)
            self.assertEqual(service.stats["duplicate"], 0)
            self.assertEqual(service.stats["rejected"], 0)

    def test_refused_winner_rpc_failure_or_rejection_never_claims_ack(self):
        for version in (7, 8):
            for failure in (RuntimeError("native RPC lost"), "bad-block"):
                service, gate = self.service(version)
                gate.receive.side_effect = AdmissionRefused(decision())
                if isinstance(failure, Exception):
                    gate.rpc.side_effect = failure
                    counter = "candidate_rpc_failures"
                else:
                    gate.rpc.return_value = failure
                    counter = "candidate_rejections"
                with self.assertRaises(AdmissionRefused):
                    self.submit(service)
                gate.rpc.assert_called_once_with("submitblock", b"exact-old-block".hex())
                self.assertEqual(service.stats[counter], 1)
                self.assertEqual(service.stats["acknowledged"], 0)
                self.assertEqual(service.stats["accepted_candidates"], 0)

    def test_exact_duplicate_winner_remains_successful_without_new_credit(self):
        for version in (7, 8):
            service, gate = self.service(version)
            gate.receive.return_value = False
            if version == 8:
                service.controller.set_admission_paused(True)
            self.assertTrue(self.submit(service))
            gate.rpc.assert_called_once_with("submitblock", b"exact-old-block".hex())
            self.assertEqual(service.stats["duplicate"], 1)
            self.assertEqual(service.stats["capacity_refused"], 0)
            self.assertEqual(service.stats["acknowledged"], 0)
            if version == 8:
                self.assertTrue(service.controller.status()["admission_paused"])
                self.assertEqual(service.controller.status()["window_accepted_work"], 0)

    def test_invalid_admission_exception_keeps_its_original_rejection_path(self):
        for version in (7, 8):
            service, gate = self.service(version)
            gate.receive.side_effect = ValueError("invalid native proof")
            with self.assertRaisesRegex(ValueError, "invalid native proof"):
                self.submit(service)
            gate.rpc.assert_not_called()
            self.assertEqual(service.stats["capacity_refused"], 0)
            self.assertEqual(service.stats["acknowledged"], 0)

    def test_owner_service_classifies_capacity_separately(self):
        service, gate = self.service(8)
        gate.receive.side_effect = AdmissionRefused(decision())
        service.scheduler.poll = Mock(return_value=None)
        service.latch.check = Mock(return_value=True)
        request = _Request("submit", (bytes(4), self.params))
        service.requests.put_nowait(request)
        proof = SimpleNamespace(hash_int=128, header=b"exact-old-header", block=b"exact-old-block")
        with patch("hash_stratum.proof_from_sia", return_value=proof):
            service.service_once(max_requests=1)
        self.assertTrue(request.done.is_set())
        self.assertIsInstance(request.error, AdmissionRefused)
        self.assertEqual(service.stats["capacity_refused"], 1)
        self.assertEqual(service.stats["rejected"], 0)
        gate.admission_status.assert_not_called()  # No expensive status walk per service poll.

    def test_existing_stratum_error_reply_distinguishes_capacity_and_allows_retry(self):
        service, unused_gate = self.service(7)
        service._enqueue = Mock(side_effect=[AdmissionRefused(decision()), True])
        self.assertEqual(service._submit_response(4, bytes(4), self.params),
                         {"id": 4, "result": False, "error": [20, "local-admission-capacity", None]})
        self.assertEqual(service._submit_response(5, bytes(4), self.params),
                         {"id": 5, "result": True, "error": None})
        service._enqueue.side_effect = ValueError("invalid client work")
        with self.assertRaisesRegex(ValueError, "invalid client work"):
            service._submit_response(6, bytes(4), self.params)

    def test_drain_and_resume_do_not_turn_missing_acks_into_easier_work(self):
        service, gate = self.service(8)
        gate.admission_status.return_value = decision()
        self.now = 100
        service._before_vardiff_build()
        self.assertEqual(service.controller.current_work_bits, 4)
        self.assertTrue(service.controller.status()["admission_paused"])
        self.now = 200
        service._before_vardiff_build()
        gate.admission_status.return_value = decision("OPEN")
        self.now = 300
        service._before_vardiff_build()
        self.assertEqual(service.controller.current_work_bits, 4)
        self.assertFalse(service.controller.status()["admission_paused"])
        self.assertEqual(service.controller.status()["window_elapsed_seconds"], 0)
        self.assertEqual(service.controller.status()["observations"], 0)
        self.assertEqual(gate.admission_status.call_count, 3)

    def test_new_ack_resumes_fresh_window_with_original_assignment(self):
        service, gate = self.service(8, native_bits=0x1d00ffff)
        gate.receive.side_effect = AdmissionRefused(decision())
        with self.assertRaises(AdmissionRefused):
            self.submit(service, 1 << 225)
        self.now = 100
        gate.share_work_bits = 9
        gate.receive.side_effect = None
        self.assertTrue(self.submit(service, 1 << 225))
        status = service.controller.status()
        self.assertFalse(status["admission_paused"])
        self.assertEqual(status["window_elapsed_seconds"], 0)
        self.assertEqual(status["window_accepted_work"], 16)
        self.assertEqual(service.stats["acknowledged"], 1)
        self.assertEqual(service.stats["capacity_refused"], 1)

    def build_pressure(self):
        service, gate = self.service(8)
        service.latch.clock = lambda: self.now
        service.latch.observe("aa" * 32)
        blocked = AdmissionRefused(AdmissionDecision("DRAIN", False, False,
            ("resource-budget",), ("empty_settlement",), None, "aa" * 32, 1, 0, 0, 0))
        gate.admission_status.side_effect = [blocked, decision("OPEN")]
        authorization = SimpleNamespace(native_parent="aa" * 32)
        gate.prepare_native_authorization = Mock(return_value=authorization)
        gate.ready_for_dispatch = Mock(return_value=True)
        gate.ready_for_continued_work = Mock(return_value=True)
        service.scheduler._publish = Mock(return_value=True)
        return service, gate, authorization

    def test_blocked_build_returns_and_retries_on_timer_without_status_spin(self):
        service, gate, authorization = self.build_pressure()
        self.assertIsNone(service.service_once())
        self.assertTrue(service.controller.status()["admission_paused"])
        self.assertEqual(service.stats["capacity_refused"], 1)
        self.assertEqual(service.stats["rejected"], 0)
        for now in (0, 0.1, 0.5, 0.999):
            self.now = now
            self.assertIsNone(service.service_once())
        self.assertEqual(gate.admission_status.call_count, 1)
        gate.prepare_native_authorization.assert_not_called()
        self.now = 1
        self.assertIs(service.service_once(), authorization)
        self.assertEqual(gate.admission_status.call_count, 2)
        gate.prepare_native_authorization.assert_called_once()
        self.assertFalse(service.controller.status()["admission_paused"])
        self.assertIsNone(service._capacity_retry_at)

    def test_fresh_native_generation_bypasses_capacity_retry_delay(self):
        service, gate, authorization = self.build_pressure()
        self.assertIsNone(service.service_once())
        self.now = 0.1
        service.latch.observe("bb" * 32)
        self.assertIs(service.service_once(), authorization)
        self.assertEqual(gate.admission_status.call_count, 2)
        gate.prepare_native_authorization.assert_called_once()

    def test_blocked_refresh_retires_advertised_work_before_retrying(self):
        service, gate, authorization = self.build_pressure()
        service.scheduler._active = authorization
        service.scheduler._next_refresh = 0
        service.current = SimpleNamespace(authorization=authorization, generation=service.latch.generation)
        client = Mock()
        service.latch.sockets.add(client)
        self.assertIsNone(service.service_once())
        client.shutdown.assert_called_once()
        self.assertIsNone(service.current)
        self.assertIsNone(service.scheduler.active)
        self.assertFalse(service.latch.check())
        service.latch.observe("aa" * 32)
        self.now = 0.1
        self.assertIsNone(service.service_once())
        self.assertEqual(gate.admission_status.call_count, 1)

    def test_issued_submissions_are_processed_during_build_pressure_backoff(self):
        service, gate, unused_authorization = self.build_pressure()
        service.service_once()
        gate.receive.return_value = False
        request = _Request("submit", (bytes(4), self.params))
        service.requests.put_nowait(request)
        proof = SimpleNamespace(hash_int=128, header=b"exact-old-header", block=b"exact-old-block")
        self.now = 0.1
        with patch("hash_stratum.proof_from_sia", return_value=proof):
            self.assertIsNone(service.service_once(max_requests=1))
        self.assertTrue(request.done.is_set())
        self.assertTrue(request.result)
        self.assertIsNone(request.error)
        self.assertEqual(service.stats["duplicate"], 1)
        gate.rpc.assert_called_once_with("submitblock", b"exact-old-block".hex())
        self.assertEqual(gate.admission_status.call_count, 1)

    def test_noncapacity_build_failure_keeps_its_original_error(self):
        service, gate, unused_authorization = self.build_pressure()
        gate.admission_status.side_effect = ValueError("missing or invalid native context")
        with self.assertRaisesRegex(ValueError, "missing or invalid native context"):
            service.service_once()
        self.assertEqual(service.stats["capacity_refused"], 0)
        self.assertIsNone(service._capacity_retry_at)

    def test_non_dispatchable_pressure_pauses_before_preserving_refusal(self):
        service, gate = self.service(8)
        service.controller.observe(4)
        refusal = AdmissionRefused(decision())
        gate.admission_status.side_effect = refusal
        self.now = 100
        with self.assertRaises(AdmissionRefused) as caught:
            service._before_vardiff_build()
        self.assertIs(caught.exception, refusal)
        self.assertEqual(service.last_admission_decision, refusal.decision)
        self.assertEqual(service.controller.current_work_bits, 4)
        self.assertTrue(service.controller.status()["admission_paused"])
        self.assertEqual(service.controller.status()["window_accepted_work"], 0)
        gate.set_share_work_bits.assert_not_called()

    def test_estimator_failure_happens_after_exact_native_candidate_submission(self):
        service, gate = self.service(8)
        service.controller.set_admission_paused = Mock(side_effect=ValueError("controller clock failed"))
        gate.receive.side_effect = AdmissionRefused(decision())
        with self.assertRaisesRegex(ValueError, "controller clock failed"):
            self.submit(service)
        gate.rpc.assert_called_once_with("submitblock", b"exact-old-block".hex())
        self.assertEqual(service.stats["acknowledged"], 0)
        self.assertEqual(service.stats["accepted_candidates"], 1)


if __name__ == "__main__":
    unittest.main()
