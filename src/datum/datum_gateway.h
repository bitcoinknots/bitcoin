/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024 Bitcoin Ocean, LLC & Jason Hughes
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef _DATUM_GATEWAY_H_
#define _DATUM_GATEWAY_H_

#include <stdint.h>

#ifndef GIT_COMMIT_HASH
	#define GIT_COMMIT_HASH "dbc3b143589842feb606a409b40cd70f67117b45"
#endif

/* Bitcoin Purity Stage 1 bounds Stratum input lines independently from the
 * larger output buffer required for coinbase-bearing mining.notify messages. */
#define DATUM_STRATUM_MAX_MESSAGE_SIZE 16384

#ifdef _MSC_VER
#include <stdlib.h>
#define __builtin_expect(value, expected) (value)
#define __builtin_bswap16 _byteswap_ushort
#define __builtin_bswap32 _byteswap_ulong
#define __builtin_bswap64 _byteswap_uint64
#define strdup _strdup
#endif

// For SV1
// client buffer must be large enough to hold entire coinbase in hex at max size
// TODO: Make somewhat more dynamic without having to hammer [cm]alloc
#define CLIENT_BUFFER ((16384*3)+1024)

// in ascii hex
#define STRATUM_COINBASE1_MAX_LEN 1024
#define STRATUM_COINBASE2_MAX_LEN 32768

#define MAX_COINBASE_TXN_SIZE_BYTES (((STRATUM_COINBASE1_MAX_LEN+STRATUM_COINBASE2_MAX_LEN)>>1)+64)

#define STRATUM_JOB_INDEX_XOR ((uint16_t)0xC0DE)

void datum_print_banner(void);

extern const char *datum_gateway_config_filename;

extern const char * const *datum_argv;

#endif
