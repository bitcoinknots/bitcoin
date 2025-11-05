// Copyright (c) 2025 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

// Backward-compatibility header. Prefer including <mapport_hooks.h> directly.
// This header provides a namespace alias so existing includes continue to work
// without referencing the term "testing" in production symbols.
#include <mapport_hooks.h>

namespace mapport_testing = mapport_hooks;
