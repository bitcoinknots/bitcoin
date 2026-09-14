#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Cooperative DATUM-style job cadence for the native hash-only gate.

One owner calls poll regularly and promptly on native block notifications.
Normal refreshes start after 40 seconds by default. New native parents bypass
that timer. This is a local adapter, not a Stratum server or a background thread.
Synchronous native construction can delay servicing the next notification.
"""
import math
import os
import threading
import time


class HashJobScheduler:
    def __init__(self, gate, *, sign_owner, publish, withdraw,
                 work_update_seconds=40, clock=time.monotonic, before_build=None):
        if (type(work_update_seconds) is not int or not 5 <= work_update_seconds <= 120 or
                any(not callable(value) for value in (sign_owner, publish, withdraw, clock))):
            raise ValueError("job cadence requires 5..120 seconds and callable adapters")
        if before_build is not None and not callable(before_build):
            raise ValueError("scheduled before_build must be callable")
        self.gate = gate
        self._before_build = before_build
        self._sign_owner, self._publish, self._withdraw, self._clock = sign_owner, publish, withdraw, clock
        self._interval = work_update_seconds
        self._owner = os.getpid(), threading.get_ident()
        self._busy = self._closed = False
        self._withdraw_pending = False
        self._active = self._next_refresh = self._last_clock = None
        self.last_update_reason = None
        self.last_prepare_seconds = None
        self.last_due_lateness_seconds = None

    @property
    def active(self):
        return self._active

    @property
    def next_refresh_at(self):
        return self._next_refresh

    @property
    def work_update_seconds(self):
        return self._interval

    @property
    def withdrawal_pending(self):
        return self._withdraw_pending

    def _enter(self, *, allow_closed=False):
        if self._owner != (os.getpid(), threading.get_ident()):
            raise RuntimeError("job scheduler requires its original owner thread and process")
        if (self._closed and not allow_closed) or self._busy:
            raise RuntimeError("job scheduler is closed or reentrant")
        self._busy = True

    def _now(self):
        value = self._clock()
        if (type(value) not in (int, float) or not math.isfinite(value) or value < 0 or
                (self._last_clock is not None and value < self._last_clock)):
            raise ValueError("job scheduler requires a finite monotonic clock")
        self._last_clock = value
        return value

    def _retire(self, *, force=False):
        had_work = self._active is not None
        self._active = self._next_refresh = None
        self._withdraw_pending |= had_work or force
        if self._withdraw_pending:
            self._withdraw()
            self._withdraw_pending = False

    def poll(self):
        """Publish one due job, or return None while the current job continues.

        publish receives the exact authorization and must return True only
        after arranging full snapshot availability and handing its immutable
        work to the mining transport. withdraw must stop that transport
        advertising current work, returning normally only on success. Neither callback
        may reenter this scheduler or use the sole-owner gate concurrently.

        New receipts and mempool events do not move the deadline. A normal
        refresh keeps the old fixed job while its replacement is constructed;
        a changed native context retires it before construction. Any failure
        attempts to retire advertised work; failed withdrawal blocks further
        construction/publication until a later poll or close retries it.
        A solved old candidate is never rewritten or
        deleted. The deadline is a scheduling target, not a validity deadline.
        """
        self._enter()
        publishing = False
        try:
            if self._withdraw_pending:
                self._retire()
            now = self._now()
            reason = "initial"
            if self._active is not None:
                if not self.gate.ready_for_continued_work(self._active):
                    self._retire()
                    reason = "context"
                elif now < self._next_refresh:
                    return None
                else:
                    reason = "interval"
            self.last_due_lateness_seconds = (max(0, now - self._next_refresh)
                if self._next_refresh is not None else 0)
            started = now
            # A controller may assign only the future job at this due boundary.
            # New receipts alone never invoke this hook or move the deadline.
            if self._before_build is not None:
                self._before_build()
            block, snapshot = self.gate.make_native(sign_owner=self._sign_owner)
            authorization = self.gate.authorize(block.serialize(), snapshot.serialize())
            if not self.gate.ready_for_dispatch(authorization):
                raise ValueError("job changed before scheduled dispatch; prepare a fresh job")
            self.last_prepare_seconds = self._now() - started
            publishing = True
            if self._publish(authorization) is not True:
                raise ValueError("mining transport did not confirm job handoff")
            # A callback can observe a new receipt or a native tip change.
            # Receipts after the strict handoff fence preserve the issued
            # cutoff, but a new parent/profile or damaged journal stops work.
            if not self.gate.ready_for_continued_work(authorization):
                raise ValueError("native context changed during scheduled dispatch")
            completed = self._now()
            deadline = completed + self._interval
            if not math.isfinite(deadline) or deadline <= completed:
                raise ValueError("job scheduler clock cannot represent its refresh deadline")
            self._active = authorization
            self._next_refresh = deadline
            self.last_update_reason = reason
            return authorization
        except BaseException:
            # A failed withdrawal already latched an unknown transport state.
            # Retry it on the next call, without building or publishing first.
            if not self._withdraw_pending:
                self._retire(force=publishing)
            raise
        finally:
            self._busy = False

    def close(self):
        """Withdraw work; retry failed withdrawal even after closing.

        The caller retains ownership of gate.close(). A closed scheduler
        cannot resume polling, including while shutdown needs another retry.
        """
        self._enter(allow_closed=True)
        try:
            self._closed = True
            self._retire()
        finally:
            self._busy = False

    def invalidate(self):
        """Owner-side retirement after an external transport context change.

        A separate transport may already have stopped sockets during a blocked
        build. Call this after control returns to the owner to prevent a recovered
        native observation from reviving an old handoff. The next poll constructs
        fresh work and still performs the normal strict dispatch fence.
        """
        self._enter()
        try:
            self._retire()
        finally:
            self._busy = False
