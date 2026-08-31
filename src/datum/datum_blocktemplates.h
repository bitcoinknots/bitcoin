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

#ifndef _DATUM_BLOCKTEMPLATE_H_
#define _DATUM_BLOCKTEMPLATE_H_

#ifndef uint64_t
	#include <stdint.h>
#endif

#ifndef json_t
	#include <jansson.h>
#endif

#ifndef bool
	#include <stdbool.h>
#endif

#include "datum_gateway.h"

#define MAX_TEMPLATES_IN_MEMORY 32 // 32*30 seconds = 16 minutes of work remembered

// consensus rules:
// --- max sigops = 80000
// --- max size   = 4000000
// --- max weight = 4000000

#define MAX_BLOCK_SIZE_BYTES 4000000

// Assumption notes

// max possible transactions = 16394-ish .. close enough to say 16384, since we're just not going to be idiots
// max non-segwit data = 1000000

// Maximum possible inputs spent in a block = ~24400
// 80 byte block header
// 1 byte txcount
// coinbase txn ~150 bytes
// --- one giant transaction
// 			4 bytes version
//			3 byte input count (up to 65535)
//				INPUT: 36 byte outpoint, 1 byte scriptsiglen (0), no scriptsig (segwit), 4 byte sequence
//
//			1 byte output count
//				OUTPUT: 8 byte value, 1 byte scriptlen, 22 bytes script
//		4 bytes lock time
//	txn wo/inputs = 4+3+1+8+1+22+4 = 43 bytes
//  block with coinbase + txn wo/inputs = 80+1+150+43 = 274 bytes
//  remaining bytes (1000000-274) / input size (41) = ~24383

// Maximum possible transactions in a block = ~16400
// 80 byte block header
// 1 byte txcount
// coinbase txn ~150 bytes
// --- one giant transaction
// 			4 bytes version
//			1 byte input count (1)
//				INPUT: 36 byte outpoint, 1 byte scriptsiglen (0), no scriptsig (segwit/OP_TRUE), 4 byte sequence
//			1 byte output count
//				OUTPUT: 8 byte value, 1 byte scriptlen, OP_TRUE (1 byte)
//		4 bytes lock time
// txn size = 4+1+36+1+4+1+8+1+1+4 = 61 bytes
// remaining bytes (1000000-80-1-150) / 61 = ~16390

// maximum possible UTXOs in a block = ~100000
// 80 byte block header
// 1 byte txcount
// coinbase txn ~150 bytes
// --- one giant transaction
// 			4 bytes version
//			1 byte input count (1)
//				INPUT: 36 byte outpoint, 1 byte scriptsiglen (0), no scriptsig (segwit/OP_TRUE), 4 byte sequence
//			3 byte output count
//				OUTPUT: 8 byte value, 1 byte scriptlen, OP_TRUE (1 byte)
//		4 bytes lock time
// txn size wo/outputs = 4+1+36+1+4+2+4 = 52 bytes
// remaining bytes (1000000-80-1-150-52) / 10 = ~99972

// txn struct = ~264 bytes

typedef struct T_DATUM_TEMPLATE_TXN {
	// *1-based* index of this transaction in the original GBT call
	// max txns in a block is about 16,400 (see notes above)
	uint16_t	index_raw;
	
	// transaction ID in ASCII hex + calc'd NBO, as provided by GBT
	char txid_hex[72]; // big endian hex
	uint8_t txid_bin[32]; // little endian binary
	
	// "hash" (segwit) ID in ASCII hex + calc'd NBO, as provided by GBT
	char hash_hex[72]; // big endian hex
	uint8_t hash_bin[32]; // little endian binary
	
	// size of the transaction in bytes
	uint32_t	size;
	
	// "weight" of the transaction
	// vBytes = weight>>2
	uint32_t	weight;
	
	// transaction fee paid, in sats
	uint64_t	fee_sats;
	
	// signature operations
	uint32_t	sigops;
	
	// binary of the raw transaction data, as provided by GBT
	// --- this should point to data allocated as a chunk in the base template
	uint8_t		*txn_data_binary;
	char *txn_data_hex;
	
	// Info on dependancies returned by GBT
	// Who do I depend on?
	// if depends_on_count > 0, then this txn relies on some other txn in the GBT
	// it's possible those txns have other txns they depend on as well
	//uint16_t	depends_on_count;
	//uint16_t	*depends_on_list;
} T_DATUM_TEMPLATE_TXN;

typedef struct {
	uint16_t	local_index; // tie to stratum work
	
	uint64_t	coinbasevalue; //
	uint64_t	mintime; //
	uint64_t	curtime; //
	uint64_t	sizelimit; //
	uint64_t	weightlimit; //
	uint32_t	height; //
	uint32_t	version; //
	uint32_t	sigoplimit; //
	
	char		bits[9]; //
	char		dummy[7]; // unused, possibly for alignment
	uint8_t		bits_bin[4]; //
	uint32_t	bits_uint; //
	char		previousblockhash[72]; //
	uint8_t		previousblockhash_bin[32]; //
	char		default_witness_commitment[96]; //
	uint8_t		default_witness_commitment_bin[48]; //
	
	char		block_target_hex[72]; //
	uint8_t		block_target[32]; // calculated from bits
	
	uint32_t 	txn_count;
	uint32_t	txn_total_weight;
	uint32_t	txn_total_size;
	uint32_t	txn_total_sigops;
	
	T_DATUM_TEMPLATE_TXN *txns;
	uint32_t	txn_data_offset;
	
	// Pointer to allocated data for this particular template copy
	void		*local_data;
	uint32_t	local_data_size;
} T_DATUM_TEMPLATE_DATA;

extern const char *datum_blocktemplates_error;

int datum_template_init(void);
T_DATUM_TEMPLATE_DATA *datum_gbt_parser(json_t *gbt);
void *datum_gateway_template_thread(void *args);
void datum_blocktemplates_notifynew_sighandler();
void datum_blocktemplates_notifynew(const char *prevhash, int height);
void datum_blocktemplates_notify_othercause();

#endif
