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
 * Copyright (c) 2024-2025 Bitcoin Ocean, LLC & Jason Hughes
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

#ifndef _DATUM_UTILS_H_
#define _DATUM_UTILS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "datum_logger.h"

void datum_utils_init(void);

extern unsigned int datum_test_failed;
bool datum_test_fail_(const char *expr, const char *file, unsigned int line, const char *func);
#define datum_test_(expr, fake_expr, line, fake_func) \
	((expr) ? true : datum_test_fail_(fake_expr, __FILE__, line, fake_func))
#define datum_test(expr) \
	datum_test_(expr, #expr, __LINE__, __func__)

uint64_t monotonic_time_seconds(void);
uint64_t current_time_millis(void);
uint64_t current_time_micros(void);
uint64_t get_process_uptime_seconds(void);
unsigned char hex2bin_uchar(const char *in);
void build_hex_lookup(void);
bool my_sha256(void *digest, const void *buffer, size_t length);
void nbits_to_target(uint32_t nbits, uint8_t *target);
int compare_hashes(const uint8_t *hash1, const uint8_t *hash2);
unsigned long long block_reward(unsigned int block_height);
int append_bitcoin_varint_hex(uint64_t n, char *s);
int append_UNum_hex(uint64_t n, char *s);
void panic_from_thread(int a);
bool double_sha256(void *out, const void *in, size_t length);
void hex_to_bin_le(const char *hex, unsigned char *bin);
void hex_to_bin(const char *hex, unsigned char *bin);
void hash2hex(unsigned char *bytes, char *hexString);
void get_target_from_diff(unsigned char *result, uint64_t diff);
uint64_t roundDownToPowerOfTwo_64(uint64_t x);
int addr_2_output_script(const char *addr, unsigned char *script, int max_len);
int output_script_2_addr(const unsigned char *script, const int len, char *addr);
int base64_decode(const char *in, size_t inLen, unsigned char *out, size_t *outLen);
void uchar_to_hex(char *s, const unsigned char b);
int get_bitcoin_varint_len_bytes(uint64_t n);
bool strncpy_uachars(char *out, const char *in, size_t maxlen);
bool strncpy_workerchars(char *out, const char *in, size_t maxlen);
long double calc_network_difficulty(const char *bits_hex);
unsigned char floorPoT(uint64_t x);
uint64_t datum_siphash(const void *src, uint64_t sz, const unsigned char key[16]);
uint64_t datum_siphash_mod8(const void *src, uint64_t sz, const unsigned char key[16]);
unsigned int datum_double_precision(double *inout_dbl);
uint64_t datum_atoi_strict_u64(const char *s, size_t size);
int datum_atoi_strict(const char *s, size_t size);
bool datum_str_to_bool_strict(const char *s, bool *out);
char **datum_deepcopy_charpp(const char * const *p);
void datum_reexec();
bool datum_secure_strequals(const char *secret, const size_t secret_len, const char *guess);
const char *dynamic_hash_unit(double *inout_hashrate);


static inline size_t datum_align_sz(const size_t min_sz, const size_t alignment) {
	return (min_sz + alignment - 1) / alignment * alignment;
}


static inline
uint8_t upk_u8(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return buf[offset];
}

#define upk_u8le(buf, offset)  upk_u8(buf, offset)

static inline
uint16_t upk_u16le(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint16_t)buf[offset+0]) <<    0)
	     | (((uint16_t)buf[offset+1]) <<    8);
}

static inline
uint32_t upk_u32le(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint32_t)buf[offset+0]) <<    0)
	     | (((uint32_t)buf[offset+1]) <<    8)
	     | (((uint32_t)buf[offset+2]) << 0x10)
	     | (((uint32_t)buf[offset+3]) << 0x18);
}

static inline
uint64_t upk_u64le(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint64_t)buf[offset+0]) <<    0)
	     | (((uint64_t)buf[offset+1]) <<    8)
	     | (((uint64_t)buf[offset+2]) << 0x10)
	     | (((uint64_t)buf[offset+3]) << 0x18)
	     | (((uint64_t)buf[offset+4]) << 0x20)
	     | (((uint64_t)buf[offset+5]) << 0x28)
	     | (((uint64_t)buf[offset+6]) << 0x30)
	     | (((uint64_t)buf[offset+7]) << 0x38);
}


static inline
void pk_u8(void * const bufp, const int offset, const uint8_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset] = nv;
}

#define pk_u8le(buf, offset, nv)  pk_u8(buf, offset, nv)

static inline
void pk_u16le(void * const bufp, const int offset, const uint16_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset+0] = (nv >>    0) & 0xff;
	buf[offset+1] = (nv >>    8) & 0xff;
}

static inline
void pk_u32le(void * const bufp, const int offset, const uint32_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset+0] = (nv >>    0) & 0xff;
	buf[offset+1] = (nv >>    8) & 0xff;
	buf[offset+2] = (nv >> 0x10) & 0xff;
	buf[offset+3] = (nv >> 0x18) & 0xff;
}

static inline
void pk_u64le(void * const bufp, const int offset, const uint64_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset+0] = (nv >>    0) & 0xff;
	buf[offset+1] = (nv >>    8) & 0xff;
	buf[offset+2] = (nv >> 0x10) & 0xff;
	buf[offset+3] = (nv >> 0x18) & 0xff;
	buf[offset+4] = (nv >> 0x20) & 0xff;
	buf[offset+5] = (nv >> 0x28) & 0xff;
	buf[offset+6] = (nv >> 0x30) & 0xff;
	buf[offset+7] = (nv >> 0x38) & 0xff;
}


extern volatile int panic_mode;

#endif
