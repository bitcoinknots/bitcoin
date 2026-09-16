#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exact native errors that permit bounded local evidence recovery."""


def missing_snapshot_data(error):
    """Match the native code/message pair, never free-form exception text.

    AuthServiceProxy carries structured JSON-RPC fields in ``error``. Adapters
    may instead expose an integer ``code`` and one exact message argument.
    The native endpoint combines several unavailable conditions into this
    pair, so a match permits one attempt, not an assumption of recoverability.
    """
    detail = getattr(error, "error", None)
    if detail is not None:
        if type(detail) is not dict:
            return False
        code, message = detail.get("code"), detail.get("message")
    else:
        code = getattr(error, "code", None)
        message = error.args[0] if len(error.args) == 1 else None
    return (type(code) is int and code == -25 and type(message) is str and
            message == "sharepool-hash-data-missing")
