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

#include <string.h>
#include <curl/curl.h>
#include <jansson.h>

#include "datum_utils.h"
#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_embedded.h"
#include "datum_thread.h"
#include "datum_time.h"
#include "datum_submitblock.h"

pthread_mutex_t submitblock_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t submitblock_cond = PTHREAD_COND_INITIALIZER;
int submit_block_triggered = 0;
const char *submitblock_ptr = NULL;
char submitblock_hash[256] = { 0 };
static pthread_t pthread_datum_submitblock_thread;
static bool datum_submitblock_started;

void preciousblock(CURL *curl, char *blockhash) {
	json_t *json;
	char rpc_data[384];
	
	snprintf(rpc_data, sizeof(rpc_data), "{\"method\":\"preciousblock\",\"params\":[\"%s\"],\"id\":1}", blockhash);
	json = bitcoind_json_rpc_call(curl, &datum_config, rpc_data);
	if (!json) return;
	
	json_decref(json);
	return;
}

void datum_submitblock_doit(CURL *tcurl, char *url, const char *submitblock_req, const char *block_hash_hex) {
	json_t *r;
	char *s = NULL;
	// TODO: Move these types of things to the conf file
	if (!url) {
		r = bitcoind_json_rpc_call(tcurl, &datum_config, submitblock_req);
	} else {
		r = json_rpc_call(tcurl, url, NULL, submitblock_req);
	}
	if (!r) {
		// oddly, this means success here.
		DLOG_INFO("Block %s submitted to upstream node successfully!",block_hash_hex);
	} else {
		s = json_dumps(r, JSON_ENCODE_ANY);
		if (!s) {
			DLOG_WARN("Upstream node rejected our block! (unknown)");
		} else {
			DLOG_WARN("Upstream node rejected our block! (%s)",s);
			free(s);
		}
		json_decref(r);
	}
	
	// precious block!
	preciousblock(tcurl, submitblock_hash);
}

void *datum_submitblock_thread(void *ptr) {
	CURL *tcurl = NULL;
	int i;
	
	tcurl = curl_easy_init();
	if (!tcurl) {
		DLOG_FATAL("Could not initialize cURL for submitblock!!! This is REALLY REALLY BAD.  Like accidentally calling your wife your ex-girlfriend's name bad.");
		panic_from_thread(__LINE__);
	}
	
	DLOG_DEBUG("Submitblock thread active");
	
	while (!datum_embedded_should_stop()) {
		// Lock the mutex before waiting on the condition variable
		pthread_mutex_lock(&submitblock_mutex);
		
		// Wait for the event to be triggered
		while (!submit_block_triggered && !datum_embedded_should_stop()) {
			pthread_cond_wait(&submitblock_cond, &submitblock_mutex);
		}
		if (datum_embedded_should_stop()) {
			pthread_mutex_unlock(&submitblock_mutex);
			break;
		}
		
		if (submitblock_ptr != NULL) {
			DLOG_DEBUG("SUBMITTING BLOCK TO OUR NODE!");
			
			datum_submitblock_doit(tcurl,NULL,submitblock_ptr,submitblock_hash);
			
			if (datum_config.extra_block_submissions_count > 0) {
				for(i=0;i<datum_config.extra_block_submissions_count;i++) {
					DLOG_DEBUG("SUBMITTING BLOCK TO EXTRA NODE %d!",i+1);
					datum_submitblock_doit(tcurl,(char *)datum_config.extra_block_submissions_urls[i],submitblock_ptr,submitblock_hash);
				}
			}
		}
		
		// Reset the event flag
		submit_block_triggered = 0;
		
		// Unlock the mutex after processing
		pthread_mutex_unlock(&submitblock_mutex);
	}
	
	return NULL;
}

void datum_submitblock_waitfree(void) {
	pthread_mutex_lock(&submitblock_mutex);
	DLOG_DEBUG("DEBUG: Lock acquired.");
	pthread_mutex_unlock(&submitblock_mutex);
}

void datum_submitblock_trigger(const char *ptr, const char *hash) {
	// Lock the mutex before updating and triggering the event
	
	int i;
	for(i=0;i<100;i++) {
		if (pthread_mutex_trylock(&submitblock_mutex) == 0) {
			// Update the shared data
			submitblock_ptr = ptr;
			strcpy(submitblock_hash, hash);
			
			// Set the event flag and signal the condition variable
			submit_block_triggered = 1;
			pthread_cond_signal(&submitblock_cond);
			
			// Unlock the mutex
			pthread_mutex_unlock(&submitblock_mutex);
			return;
		}
		
		usleep(1000);
	}
	
	DLOG_ERROR("Could not acquire a lock on the submitblock thread after 100ms! This might be bad!");
	return;
}

void datum_submitblock_init(void) {
	// TODO: Handle rare issues.
	if (pthread_create(&pthread_datum_submitblock_thread, NULL, datum_submitblock_thread, NULL) == 0) {
		datum_submitblock_started = true;
	}
	return;
}

void datum_submitblock_interrupt(void) {
	pthread_mutex_lock(&submitblock_mutex);
	pthread_cond_broadcast(&submitblock_cond);
	pthread_mutex_unlock(&submitblock_mutex);
}

void datum_submitblock_stop(void) {
	if (!datum_submitblock_started) return;
	datum_submitblock_interrupt();
	pthread_join(pthread_datum_submitblock_thread, NULL);
	datum_submitblock_started = false;
}
