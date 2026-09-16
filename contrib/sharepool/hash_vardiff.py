#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Causal, bounded-state v8 difficulty control for one payout identity.

This estimates disclosed, accepted work per elapsed wall-clock second. It is
neither a physical hashrate attestation nor a consensus timestamp. Call observe
only after a new durable ACK, using that proof's original signed assignment.
Only a due job builder calls next_assignment; old jobs are never rewritten.
"""
import math
import os
import threading
import time

DEFAULT_TARGET_SHARE_SECONDS = 6  # Ten accepted shares per minute, per miner.


def work_bits(value):
    if type(value) is not int or not 0 <= value <= 255:
        raise ValueError("v8 share_work_bits must be an integer in 0..255")
    return value


class VardiffController:
    def __init__(self, *, initial_work_bits, target_share_seconds=DEFAULT_TARGET_SHARE_SECONDS,
                 retarget_seconds=None, min_work_bits=0, max_work_bits=255,
                 clock=time.monotonic):
        for value in (initial_work_bits, min_work_bits, max_work_bits):
            work_bits(value)
        if not min_work_bits <= initial_work_bits <= max_work_bits:
            raise ValueError("initial vardiff assignment is outside configured bounds")
        if (type(target_share_seconds) not in (int, float) or
                not 1 <= target_share_seconds <= 3600 or not callable(clock)):
            raise ValueError("vardiff target interval must be 1..3600 seconds")
        retarget_seconds = 4 * target_share_seconds if retarget_seconds is None else retarget_seconds
        if (type(retarget_seconds) not in (int, float) or
                not target_share_seconds <= retarget_seconds <= 86400):
            raise ValueError("vardiff observation window must be target interval..86400 seconds")
        self.current_work_bits = initial_work_bits
        self.target_share_seconds, self.retarget_seconds = target_share_seconds, retarget_seconds
        self.min_work_bits, self.max_work_bits = min_work_bits, max_work_bits
        self._clock, self._owner = clock, (os.getpid(), threading.get_ident())
        self._last_time = self._started = None
        self._work = self._shares = 0
        self.adjustments = self.observations = 0
        self.last_estimate = None
        self._admission_paused = False

    def _now(self):
        if self._owner != (os.getpid(), threading.get_ident()):
            raise RuntimeError("vardiff controller requires its original owner")
        value = self._clock()
        try:
            valid = (type(value) in (int, float) and math.isfinite(value) and value >= 0 and
                     (self._last_time is None or value >= self._last_time))
        except (ValueError, OverflowError, TypeError):
            valid = False
        if not valid:
            raise ValueError("vardiff controller requires a finite monotonic clock")
        self._last_time = value
        return value

    def start(self):
        """Start elapsed-time observation when the first job is published."""
        now = self._now()
        if self._started is None:
            self._started = now

    def set_admission_paused(self, paused):
        """Exclude capacity-limited windows from hashrate-driven retargeting.

        Refused work is not an idle-miner observation. Neither a partial window
        nor elapsed drain time may ease the assigned difficulty after recovery.
        Previously acknowledged work and its signed assignment are unchanged.
        """
        if type(paused) is not bool:
            raise ValueError("admission pause must be boolean")
        now = self._now()
        if paused != self._admission_paused:
            self._admission_paused = paused
            self._work = self._shares = 0
            if self._started is not None:
                self._started = now

    def observe(self, assigned_work_bits):
        """Record one newly durably acknowledged proof at its old job weight."""
        bits = work_bits(assigned_work_bits)
        self._now()
        if self._started is None:
            raise RuntimeError("vardiff observation requires published work")
        if self._admission_paused:
            return
        self._work += 1 << bits
        self._shares += 1

    def next_assignment(self):
        """At a scheduled build, change at most one bit after a full window.

        A twofold deadband avoids reacting to small fluctuations. A no-share
        window can ease one step; it cannot attest that the miner was idle.
        Mixed assignments are weighted before estimating, not counted equally.
        """
        now = self._now()
        if self._admission_paused or self._started is None or now - self._started < self.retarget_seconds:
            return self.current_work_bits
        elapsed = now - self._started
        estimate = self._work / elapsed
        desired_work = estimate * self.target_share_seconds
        current = 1 << self.current_work_bits
        change = 1 if desired_work >= 2 * current else -1 if desired_work <= current / 2 else 0
        updated = min(self.max_work_bits, max(self.min_work_bits, self.current_work_bits + change))
        self.last_estimate = {"elapsed_seconds": elapsed, "accepted_shares": self._shares,
            "accepted_work": self._work, "estimated_hashes_per_second": estimate,
            "previous_work_bits": self.current_work_bits, "next_work_bits": updated}
        self.adjustments += int(updated != self.current_work_bits)
        self.observations += 1
        self.current_work_bits = updated
        self._started, self._work, self._shares = now, 0, 0
        return updated

    def status(self):
        now = self._now()
        return {"share_work_bits": self.current_work_bits,
            "target_share_seconds": self.target_share_seconds,
            "retarget_seconds": self.retarget_seconds,
            "window_elapsed_seconds": None if self._started is None else now - self._started,
            "window_accepted_shares": self._shares, "window_accepted_work": self._work,
            "adjustments": self.adjustments, "observations": self.observations,
            "last_estimate": None if self.last_estimate is None else dict(self.last_estimate),
            "admission_paused": self._admission_paused,
            "physical_hashrate_attested": False}
