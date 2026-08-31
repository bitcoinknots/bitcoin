/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.
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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef LIBBASE58_H
#define LIBBASE58_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern size_t blkmk_address_to_script(void *out, size_t outsz, const char *addr);

extern bool (*b58_sha256_impl)(void *, const void *, size_t);

extern bool b58tobin(void *bin, size_t *binsz, const char *b58, size_t b58sz);
extern int b58check(const void *bin, size_t binsz, const char *b58, size_t b58sz);

extern bool b58enc(char *b58, size_t *b58sz, const void *bin, size_t binsz);
extern bool b58check_enc(char *b58c, size_t *b58c_sz, uint8_t ver, const void *data, size_t datasz);

#ifdef __cplusplus
}
#endif

#endif
