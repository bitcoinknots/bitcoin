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

#ifndef _DATUM_JSONRPC_H_
#define _DATUM_JSONRPC_H_

#include <curl/curl.h>
#include <jansson.h>

#include "datum_conf.h"

#ifndef JSON_INTEGER_IS_LONG_LONG
#       error "Jansson 2.0 with long long support required!"
#endif
#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads((str), 0, (err_ptr))
#else
#define JSON_LOADS(str, err_ptr) json_loads((str), (err_ptr))
#endif

// Legacy functions
#define bitcoin_rpc_url global_config.bitcoind_url
#define bitcoin_rpc_userpass global_config.bitcoind_userpass

struct data_buffer {
	void            *buf;
	size_t          len;
};
struct upload_buffer {
	const void      *buf;
	size_t          len;
};

json_t *json_rpc_call(CURL *curl, const char *url, const char *userpass, const char *rpc_req);
char *basic_http_call(CURL *curl, const char *url);
bool update_rpc_cookie(global_config_t *cfg);
void update_rpc_auth(global_config_t *cfg);
json_t *bitcoind_json_rpc_call(CURL *curl, global_config_t *cfg, const char *rpc_req);

#endif
