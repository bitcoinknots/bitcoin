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

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include <stdbool.h>

#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_utils.h"

// TODO: Clean this up.  Most of this is very old code from other parts of Eligius/OCEAN internal tools and needs
// a solid makeover.
// However, it's all quite functional, so not a top priority.

static void databuf_free(struct data_buffer *db) {
	if (!db) {
		return;
	}
	
	free(db->buf);
	memset(db, 0, sizeof(*db));
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb, void *user_data) {
	struct data_buffer *db = user_data;
	size_t len, oldlen, newlen;
	void *newmem;
	
	if (SIZE_MAX / size < nmemb) abort();
	len = size * nmemb;
	
	oldlen = db->len;
	if (SIZE_MAX - oldlen < len) abort();
	newlen = oldlen + len;
	
	newmem = realloc(db->buf, newlen + 1);
	if (!newmem) {
		return 0;
	}
	
	db->buf = newmem;
	db->len = newlen;
	memcpy(&((char *)db->buf)[oldlen], ptr, len);
	((char *)db->buf)[newlen] = 0;
	
	return len;
}

static size_t upload_data_cb(void *ptr, size_t size, size_t nmemb, void *user_data) {
	struct upload_buffer *ub = user_data;
	size_t len;
	if (SIZE_MAX / size < nmemb) nmemb = SIZE_MAX / size;
	len = size * nmemb;
	
	if (len > ub->len) len = ub->len;
	
	if (len) {
		memcpy(ptr, ub->buf, len);
		ub->buf = &((const char *)ub->buf)[len];
		ub->len -= len;
	}
	
	return len;
}

char *basic_http_call(CURL *curl, const char *url) {
	CURLcode rc;
	struct data_buffer all_data = { };
	char curl_err_str[CURL_ERROR_SIZE];
	char *out;
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); // quick timeout!
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); // quick timeout!
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	
	rc = curl_easy_perform(curl);
	if (rc) {
		DLOG_DEBUG("HTTP request failed: %s", curl_err_str);
		goto err_out;
	}
	
	out = calloc(strlen(all_data.buf)+20,1);
	if (!out) goto err_out;
	
	strcpy(out, all_data.buf);
	
	databuf_free(&all_data);
	curl_easy_reset(curl);
	return out;

err_out:
	databuf_free(&all_data);
	curl_easy_reset(curl);
	return NULL;
}

json_t *json_rpc_call_full(CURL *curl, const char *url, const char *userpass, const char *rpc_req, const char *extra_header, long * const http_resp_code_out) {
	json_t *val, *err_val, *res_val;
	CURLcode rc;
	struct data_buffer all_data = { };
	struct upload_buffer upload_data;
	json_error_t err = { };
	struct curl_slist *headers = NULL;
	char curl_err_str[CURL_ERROR_SIZE];
	bool check_for_result = true;
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, upload_data_cb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_data);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); // quick timeout!
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); // quick timeout!
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	
	if (userpass) {
		curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	}
	
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	
	upload_data.buf = rpc_req;
	upload_data.len = strlen(rpc_req);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)upload_data.len);
	
	headers = curl_slist_append(headers, "Content-type: application/json");
	headers = curl_slist_append(headers, "Expect:");
	
	if (extra_header) {
		headers = curl_slist_append(headers, extra_header);
		check_for_result = false;
	}
	
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	
	rc = curl_easy_perform(curl);
	if (rc) {
		if (http_resp_code_out) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_resp_code_out);
		DLOG_DEBUG("json_rpc_call: HTTP request failed: %s", curl_err_str);
		DLOG_DEBUG("json_rpc_call: Request was: %s",rpc_req);
		goto err_out;
	}
	
	val = JSON_LOADS(all_data.buf, &err);
	if (!val) {
		DLOG_DEBUG("JSON decode failed(%d): %s", err.line, err.text);
		goto err_out;
	}
	
	if (check_for_result) {
		res_val = json_object_get(val, "result");
		err_val = json_object_get(val, "error");
		
		if (!res_val || json_is_null(res_val) || (err_val && !json_is_null(err_val))) {
			char *s;
			
			if (err_val) {
				s = json_dumps(err_val, JSON_INDENT(3));
			} else {
				s = strdup("(unknown reason)");
			}
			
			DLOG_DEBUG("JSON-RPC call failed: %s", s);
			
			free(s);
			
			goto err_out;
		}
	}
	
	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return val;

err_out:
	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return NULL;
}

json_t *json_rpc_call(CURL *curl, const char *url, const char *userpass, const char *rpc_req) {
	return json_rpc_call_full(curl, url, userpass, rpc_req, NULL, NULL);
}

bool update_rpc_cookie(global_config_t * const cfg) {
	assert(!cfg->bitcoind_rpcuser[0]);
	FILE * const F = fopen(cfg->bitcoind_rpccookiefile, "r");
	if (!F) {
		DLOG_ERROR("Cannot %s cookie file %s", "open", datum_config.bitcoind_rpccookiefile);
		return false;
	}
	if (!(fgets(cfg->bitcoind_rpcuserpass, sizeof(cfg->bitcoind_rpcuserpass), F) && cfg->bitcoind_rpcuserpass[0])) {
		DLOG_ERROR("Cannot %s cookie file %s", "read", datum_config.bitcoind_rpccookiefile);
		return false;
	}
	return true;
}

void update_rpc_auth(global_config_t * const cfg) {
	if (datum_config.bitcoind_rpccookiefile[0] && !cfg->bitcoind_rpcuser[0]) {
		update_rpc_cookie(cfg);
	} else {
		snprintf(datum_config.bitcoind_rpcuserpass, sizeof(datum_config.bitcoind_rpcuserpass), "%s:%s", datum_config.bitcoind_rpcuser, datum_config.bitcoind_rpcpassword);
	}
}

json_t *bitcoind_json_rpc_call(CURL * const curl, global_config_t * const cfg, const char * const rpc_req) {
	long http_resp_code = -1;
	json_t *j = json_rpc_call_full(curl, cfg->bitcoind_rpcurl, cfg->bitcoind_rpcuserpass, rpc_req, NULL, &http_resp_code);
	if (j) return j;
	if (cfg->bitcoind_rpcuser[0]) return NULL;
	if (http_resp_code != 401) return NULL;
	
	// Authentication failure using cookie; reload cookie file and try again
	if (!update_rpc_cookie(cfg)) return NULL;
	return json_rpc_call(curl, cfg->bitcoind_rpcurl, cfg->bitcoind_rpcuserpass, rpc_req);
}
