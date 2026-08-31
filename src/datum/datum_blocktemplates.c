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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <jansson.h>
#include <inttypes.h>
#include <curl/curl.h>
#include <stdatomic.h>
#include <signal.h>

#include "datum_gateway.h"
#include "datum_jsonrpc.h"
#include "datum_utils.h"
#include "datum_blocktemplates.h"
#include "datum_conf.h"
#include "datum_stratum.h"
#include "datum_embedded.h"
#include "datum_thread.h"
#include "datum_time.h"

volatile sig_atomic_t new_notify = 0;
atomic_int new_notify_threadsafe = 0;
atomic_int notify_othercause = 0;
static pthread_mutex_t new_notify_lock = PTHREAD_MUTEX_INITIALIZER;
volatile char new_notify_blockhash[256] = { 0 };
volatile int new_notify_height = 0;

void datum_blocktemplates_notifynew_sighandler() {
	new_notify = 1;
}

void datum_blocktemplates_notifynew(const char * const prevhash, const int height) {
	if (prevhash && *prevhash) pthread_mutex_lock(&new_notify_lock);
	new_notify_threadsafe = 1;
	if (prevhash) {
		if (prevhash[0]) {
			strncpy((char *)new_notify_blockhash, prevhash, 66);
			if (height > new_notify_height) {
				new_notify_height = height;
			}
			pthread_mutex_unlock(&new_notify_lock);
		}
	}
}

void datum_blocktemplates_notify_othercause() {
	notify_othercause = 1;
}

T_DATUM_TEMPLATE_DATA *template_data = NULL;

int next_template_index = 0;

const char *datum_blocktemplates_error = NULL;

int datum_template_init(void) {
	char *temp = NULL, *ptr = NULL;
	int i,j;
	
	template_data = (T_DATUM_TEMPLATE_DATA *)calloc(sizeof(T_DATUM_TEMPLATE_DATA),MAX_TEMPLATES_IN_MEMORY+1);
	if (!template_data) {
		DLOG_FATAL("Could not allocate RAM for in-memory template data. :( (1)");
		return -1;
	}
	
	// TODO: Be smarter about dependent RAM data and size
	// we're storing both binary and ascii hex versions of all txns for both processing and submitblock speedups
	j = (sizeof(T_DATUM_TEMPLATE_TXN)*16384) + (MAX_BLOCK_SIZE_BYTES*3) + 2000000;
	temp = calloc(j, MAX_TEMPLATES_IN_MEMORY);
	if (!temp) {
		DLOG_FATAL("ERROR: Could not allocate RAM for in-memory template data. :( (2)");
		return -2;
	}
	
	ptr = temp;
	for(i=0;i<MAX_TEMPLATES_IN_MEMORY;i++) {
		template_data[i].local_data = ptr;
		ptr+=j;
		template_data[i].local_data_size = j;
		template_data[i].local_index = i;
	}
	
	DLOG_DEBUG("Allocated %d MB of RAM for template memory", (j*MAX_TEMPLATES_IN_MEMORY)/(1024*1024));
	
	return 1;
}

void datum_template_clear(T_DATUM_TEMPLATE_DATA* p) {
	p->coinbasevalue = 0;
	p->txn_count = 0;
	p->txn_total_size = 0;
	p->txn_data_offset = 0;
	p->txn_total_weight = 0;
	p->txn_total_sigops = 0;
	p->txns = p->local_data;
}

T_DATUM_TEMPLATE_DATA *get_next_template_ptr(void) {
	T_DATUM_TEMPLATE_DATA *p;
	
	if (!template_data) return NULL;
	
	p = &template_data[next_template_index];
	
	datum_template_clear(p);
	
	next_template_index++;
	if (next_template_index >= MAX_TEMPLATES_IN_MEMORY) {
		next_template_index = 0;
	}
	
	return p;
}

T_DATUM_TEMPLATE_DATA *datum_gbt_parser(json_t *gbt) {
	T_DATUM_TEMPLATE_DATA *tdata;
	const char *s;
	int i,j;
	json_t *tx_array, *jval;
	
	tdata = get_next_template_ptr();
	if (!tdata) {
		DLOG_ERROR("Could not get a template pointer.");
		return NULL;
	}
	
	tdata->height = json_integer_value(json_object_get(gbt, "height"));
	if (!tdata->height) {
		DLOG_ERROR("Missing data from GBT JSON (height)");
		return NULL;
	}
	
	tdata->coinbasevalue = json_integer_value(json_object_get(gbt, "coinbasevalue"));
	if (!tdata->coinbasevalue) {
		DLOG_ERROR("Missing data from GBT JSON (coinbasevalue)");
		return NULL;
	}
	
	tdata->mintime = json_integer_value(json_object_get(gbt, "mintime"));
	if (!tdata->mintime) {
		DLOG_ERROR("Missing data from GBT JSON (mintime)");
		return NULL;
	}
	
	tdata->sigoplimit = json_integer_value(json_object_get(gbt, "sigoplimit"));
	if (!tdata->sigoplimit) {
		DLOG_ERROR("Missing data from GBT JSON (sigoplimit)");
		return NULL;
	}
	
	tdata->curtime = json_integer_value(json_object_get(gbt, "curtime"));
	if (!tdata->curtime) {
		DLOG_ERROR("Missing data from GBT JSON (curtime)");
		return NULL;
	}
	
	tdata->sizelimit = json_integer_value(json_object_get(gbt, "sizelimit"));
	if (!tdata->sizelimit) {
		DLOG_ERROR("Missing data from GBT JSON (sizelimit)");
		return NULL;
	}
	
	tdata->weightlimit = json_integer_value(json_object_get(gbt, "weightlimit"));
	if (!tdata->weightlimit) {
		DLOG_ERROR("Missing data from GBT JSON (weightlimit)");
		return NULL;
	}
	
	tdata->version = json_integer_value(json_object_get(gbt, "version"));
	if (!tdata->version) {
		DLOG_ERROR("Missing data from GBT JSON (version)");
		return NULL;
	}
	
	jval = json_object_get(gbt, "bits");
	if (json_string_length(jval) != 8) {
		DLOG_ERROR("Wrong bits length from GBT JSON");
		return NULL;
	}
	s = json_string_value(jval);
	strcpy(tdata->bits, s);
	
	jval = json_object_get(gbt, "previousblockhash");
	if (json_string_length(jval) != 64) {
		DLOG_ERROR("Missing data from GBT JSON (previousblockhash)");
		return NULL;
	}
	s = json_string_value(jval);
	strcpy(tdata->previousblockhash, s);
	
	jval = json_object_get(gbt, "target");
	if (json_string_length(jval) != 64) {
		DLOG_ERROR("Missing data from GBT JSON (target)");
		return NULL;
	}
	s = json_string_value(jval);
	strcpy(tdata->block_target_hex, s);
	
	jval = json_object_get(gbt, "default_witness_commitment");
	if (json_string_length(jval) < 38 || json_string_length(jval) > 95) {
		DLOG_ERROR("Missing data from GBT JSON (default_witness_commitment)");
		return NULL;
	}
	s = json_string_value(jval);
	strcpy(tdata->default_witness_commitment, s);
	
	// "20000000", "192e17d5", "66256be5"
	// version, bits, time
	// 192e17d5 // gbt format matches stratum for bits
	
	// stash useful binary versions of prevblockhash and nbits
	for(i=0;i<64;i+=2) {
		tdata->previousblockhash_bin[31-(i>>1)] = hex2bin_uchar(&tdata->previousblockhash[i]);
	}
	for(i=0;i<4;i++) {
		tdata->bits_bin[3-i] = hex2bin_uchar(&tdata->bits[i<<1]);
	}
	tdata->bits_uint = upk_u32le(tdata->bits_bin, 0);
	nbits_to_target(tdata->bits_uint, tdata->block_target);
	
	// store binary default witness commitment
	j = strlen(tdata->default_witness_commitment);
	for(i=0;i<j;i+=2) {
		tdata->default_witness_commitment_bin[(i>>1)] = hex2bin_uchar(&tdata->default_witness_commitment[i]);
	}
	
	// Get the txns
	tx_array = json_object_get(gbt, "transactions");
	if (!json_is_array(tx_array)) {
		DLOG_ERROR("Missing data from GBT JSON (transactions)");
		return NULL;
	}
	
	tdata->txn_count = json_array_size(tx_array);
	tdata->txn_data_offset = sizeof(T_DATUM_TEMPLATE_TXN)*tdata->txn_count;
	if (tdata->txn_count > 0) {
		if (tdata->txn_count > 16383) {
			DLOG_WARN("DATUM Gateway does not support blocks with more than 16383 transactions! %d txns in template. Truncating template to 16383 transactions.", (int)tdata->txn_count);
			tdata->txn_count = 16383;
		}
		for(i=0;i<tdata->txn_count;i++) {
			json_t *tx = json_array_get(tx_array, i);
			if (!tx) {
				DLOG_ERROR("transaction %d not found!", i);
				return NULL;
			}
			if (!json_is_object(tx)) {
				DLOG_ERROR("transaction %d is not an object!", i);
				return NULL;
			}
			
			// index (1 based, like GBT depends)
			tdata->txns[i].index_raw = i+1;
			
			// txid
			jval = json_object_get(tx, "txid");
			if (json_string_length(jval) != 64) {
				DLOG_ERROR("Missing data from GBT JSON transactions[%d] (txid)",i);
				return NULL;
			}
			s = json_string_value(jval);
			strcpy(tdata->txns[i].txid_hex, s);
			hex_to_bin_le(tdata->txns[i].txid_hex, tdata->txns[i].txid_bin);
			
			// hash
			jval = json_object_get(tx, "hash");
			if (json_string_length(jval) != 64) {
				DLOG_ERROR("Missing data from GBT JSON transactions[%d] (hash)",i);
				return NULL;
			}
			s = json_string_value(jval);
			strcpy(tdata->txns[i].hash_hex, s);
			hex_to_bin_le(tdata->txns[i].hash_hex, tdata->txns[i].hash_bin);
			
			// fee
			tdata->txns[i].fee_sats = json_integer_value(json_object_get(tx, "fee"));
			
			// sigops
			tdata->txns[i].sigops = json_integer_value(json_object_get(tx, "sigops"));
			
			// weight
			tdata->txns[i].weight = json_integer_value(json_object_get(tx, "weight"));
			
			// data
			s = json_string_value(json_object_get(tx, "data"));
			if (!s) {
				DLOG_ERROR("Missing data from GBT JSON transactions[%d] (data)",i);
				return NULL;
			}
			
			// size
			tdata->txns[i].size = strlen(s)>>1;
			
			// raw txn data
			tdata->txns[i].txn_data_binary = &((uint8_t *)tdata->local_data)[tdata->txn_data_offset];
			tdata->txn_data_offset += tdata->txns[i].size+1;
			tdata->txns[i].txn_data_hex = &((char *)tdata->local_data)[tdata->txn_data_offset];
			tdata->txn_data_offset += (tdata->txns[i].size*2)+2;
			if (tdata->txn_data_offset >= tdata->local_data_size) {
				DLOG_ERROR("Exceeded template local size with txn data!");
				return NULL;
			}
			strcpy(tdata->txns[i].txn_data_hex, s);
			hex_to_bin(s, tdata->txns[i].txn_data_binary);
			
			// tallies
			tdata->txn_total_weight+=tdata->txns[i].weight;
			tdata->txn_total_size+=tdata->txns[i].size;
			tdata->txn_total_sigops+=tdata->txns[i].sigops;
		}
	}
	
	return tdata;
}

void *datum_gateway_fallback_notifier(void *args) {
	CURL *tcurl = NULL;
	char req[512];
	char p1[72];
	p1[0] = 0;
	json_t *gbbh, *res_val;
	const char *s;
	
	tcurl = curl_easy_init();
	if (!tcurl) {
		DLOG_FATAL("Could not initialize cURL");
		panic_from_thread(__LINE__);
	}
	DLOG_DEBUG("Fallback notifier thread ready.");
	
	while(!datum_embedded_should_stop()) {
		snprintf(req, sizeof(req), "{\"jsonrpc\":\"1.0\",\"id\":\"%"PRIu64"\",\"method\":\"getbestblockhash\",\"params\":[]}", current_time_millis());
		gbbh = bitcoind_json_rpc_call(tcurl, &datum_config, req);
		if (gbbh) {
			res_val = json_object_get(gbbh, "result");
			if (!res_val) {
				DLOG_ERROR("ERROR: Could not decode getbestblockhash result!");
			} else {
				s = json_string_value(res_val);
				if (s) {
					if (strlen(s) == 64) {
						if (p1[0] == 0) {
							strncpy(p1,s,70);
						} else {
							if (strcmp(s, p1) != 0) {
								// new block?!?!?!
								datum_blocktemplates_notifynew(s,0);
								strncpy(p1,s,70);
							}
						}
					}
				}
			}
			json_decref(gbbh);
			gbbh = NULL;
		}
		sleep(1);
	}
	curl_easy_cleanup(tcurl);
	return NULL;
}

void *datum_gateway_template_thread(void *args) {
	CURL *tcurl = NULL;
	json_t *gbt = NULL, *res_val;
	uint64_t i = 0;
	char gbt_req[1024];
	int j;
	T_DATUM_TEMPLATE_DATA *t;
	bool was_notified = false;
	int wnc = 0;
	uint64_t last_block_change = 0;
	pthread_t pthread_datum_gateway_fallback_notifier;
	tcurl = curl_easy_init();
	if (!tcurl) {
		DLOG_FATAL("Could not initialize cURL");
		panic_from_thread(__LINE__);
	}
	
	if (datum_template_init() < 1) {
		DLOG_FATAL("Couldn't setup template processor.");
		panic_from_thread(__LINE__);
	}
	
	if (datum_config.mining_pool_script_len <= 0) {
		DLOG_FATAL("No validated payout script was provided by Bitcoin Purity");
		return NULL;
	}
	
	if (datum_config.bitcoind_notify_fallback) {
		// start getbestblockhash poller thread as a backup for notifications
		DLOG_DEBUG("Starting fallback block notifier");
		pthread_create(&pthread_datum_gateway_fallback_notifier, NULL, datum_gateway_fallback_notifier, NULL);
	}
	
	DLOG_DEBUG("Template fetcher thread ready.");
	
	char p1[72];
	p1[0] = 0;
	
	while(!datum_embedded_should_stop()) {
		i++;
		
		// fetch latest template
		snprintf(gbt_req, sizeof(gbt_req), "{\"method\":\"getblocktemplate\",\"params\":[{\"rules\":[\"segwit\"]}],\"id\":%"PRIu64"}",(uint64_t)((uint64_t)time(NULL)<<(uint64_t)8)|(uint64_t)(i&255));
		gbt = bitcoind_json_rpc_call(tcurl, &datum_config, gbt_req);
		
		if (!gbt) {
			datum_blocktemplates_error = "Could not fetch new template!";
			datum_embedded_record_template_result(false, datum_blocktemplates_error);
			DLOG_ERROR("Could not fetch new template from %s!", datum_config.bitcoind_rpcurl);
			for (int retry_wait = 0; retry_wait < 100 && !datum_embedded_should_stop(); ++retry_wait) usleep(10000);
			continue;
		} else {
			res_val = json_object_get(gbt, "result");
			if (!res_val) {
				datum_blocktemplates_error = "Could not decode GBT result!";
				datum_embedded_record_template_result(false, datum_blocktemplates_error);
				DLOG_ERROR("%s", datum_blocktemplates_error);
			} else {
				DLOG_DEBUG("DEBUG: calling datum_gbt_parser (new=%d)", was_notified?1:0);
				t = datum_gbt_parser(res_val);
				
				if (t) {
					datum_blocktemplates_error = NULL;
					datum_embedded_record_template_result(true, NULL);
					DLOG_DEBUG("height: %lu / value: %"PRIu64, (unsigned long)t->height, t->coinbasevalue);
					DLOG_DEBUG("--- prevhash: %s", t->previousblockhash);
					DLOG_DEBUG("--- txn_count: %u / sigops: %u / weight: %u / size: %u", t->txn_count, t->txn_total_sigops, t->txn_total_weight, t->txn_total_size);
					
					// If the previous block hash changed, or work is no longer valid, we should push clean work
					const bool new_block = strcmp(t->previousblockhash, p1);
					if (new_block || notify_othercause) {
						notify_othercause = 0;
						update_stratum_job(t,true,JOB_STATE_EMPTY_PLUS);
						if (new_block) {
							last_block_change = current_time_millis();
							strcpy(p1, t->previousblockhash);
							was_notified = false;
							DLOG_INFO("NEW NETWORK BLOCK: %s (%lu)", t->previousblockhash, (unsigned long)t->height);
						} else {
							DLOG_DEBUG("Urgent work update triggered");
						}
						
						// sleep for a milisecond
						// this will let other threads churn for a moment.  we wont get all the empty jobs blasted out in a milisecond anyway
						usleep(1000);
						
						// wait for the empties to complete
						DLOG_DEBUG("Waiting on empty work send completion...");
						for(j=0;j<4000;j++) {
							if (stratum_latest_empty_check_ready_for_full()) break;
							usleep(1001);
						}
						DLOG_DEBUG("Empty sends done!");
						
						// use this template to setup for a coinbaser wait job while the empty + full w/blank jobs are blasted
						// then this job will get blasted when its ready.
						i = datum_stratum_v1_global_subscriber_count();
						DLOG_INFO("Updating priority stratum job for block %lu: %.8f BTC, %lu txns, %lu bytes (Sent to %llu stratum client%s)", (unsigned long)t->height, (double)t->coinbasevalue / (double)100000000.0, (unsigned long)t->txn_count, (unsigned long)t->txn_total_size, (unsigned long long)i, (i!=1)?"s":"");
						update_stratum_job(t,false,JOB_STATE_FULL_PRIORITY_WAIT_COINBASER);
					} else {
						if (was_notified) {
							// we got a notification of a new block, but there doesn't seem to actually be a new block.
							// we should quickly check again instead of actually updating the stratum job
							
							pthread_mutex_lock(&new_notify_lock);
							if ((new_notify_blockhash[0] > 0) && (!strcmp(t->previousblockhash,(char *)new_notify_blockhash))) {
								// we got notified for work we already knew about
								if (new_notify_height <= 0) {
									was_notified = false;
									wnc = 0;
								} else {
									if (new_notify_height == t->height) {
										was_notified = false;
										wnc = 0;
									}
								}
							}
							if (!was_notified) {
								DLOG_DEBUG("Multi notified for block we knew details about. (%s)", new_notify_blockhash);
							} else {
								DLOG_DEBUG("Notified, however new = %s, t->previousblockhash = %s, t->height = %lu, new_notify_height = %d", new_notify_blockhash, t->previousblockhash, (unsigned long)t->height, new_notify_height);
								
								// Sometimes we call GBT before we get the signal from a blocknotify.  It's a bit of a race condition.
								// Instead of freaking out, we'll just ignore things when we get a signal that results in the same block if it was
								// within 2.5s of a previous block change.
								// absolute worst case scenario here is that there's a reverse race condition of some kind where we get our notify early and GBT is still
								// returning the old block data... then we'd be one work change delay behind things.
								// that shouldn't be possible, though, if the notify comes from the same bitcoind that we're getting our templates from
								if ((current_time_millis()-2500) < last_block_change) {
									DLOG_DEBUG("This is probably a duplicate signal, since we just changed blocks less than 2.5s ago");
									was_notified = false;
								}
								
								if (((t->height < 800000) || (t->height > 2980000)) && (new_notify_blockhash[0] == 'T')) { // some hardcoded guardrails that should last for quite some time for testnet3 and testnet4
									DLOG_DEBUG("DEBUG: TESTNET FAST FORWARD HACK!!!");
									
									// set diff 1
									strcpy(t->bits, "1d00ffff");
									for(j=0;j<4;j++) {
										t->bits_bin[3-j] = hex2bin_uchar(&t->bits[j<<1]);
									}
									t->bits_uint = upk_u32le(t->bits_bin, 0);
									nbits_to_target(t->bits_uint, t->block_target);
									// ff 20 min
									if (new_notify_height > t->curtime) {
										t->curtime = new_notify_height;
										new_notify_height = -1;
									} else {
										t->curtime += 1200;
									}
									
									DLOG_DEBUG("t->curtime = %llu", (unsigned long long)t->curtime);
									
									update_stratum_job(t,true,JOB_STATE_FULL_PRIORITY_WAIT_COINBASER);
									new_notify_blockhash[0] = 0;
									was_notified = false;
								}
							}
							pthread_mutex_unlock(&new_notify_lock);
						} else {
							i = datum_stratum_v1_global_subscriber_count();
							DLOG_INFO("Updating standard stratum job for block %lu: %.8f BTC, %lu txns, %lu bytes (Sent to %llu stratum client%s)", (unsigned long)t->height, (double)t->coinbasevalue / (double)100000000.0, (unsigned long)t->txn_count, (unsigned long)t->txn_total_size, (unsigned long long)i, (i!=1)?"s":"");
							update_stratum_job(t,false,JOB_STATE_FULL_NORMAL_WAIT_COINBASER);
						}
					}
				}
			}
			json_decref(gbt);
		}
		gbt = NULL;
		
		if ((!was_notified) || (new_notify || new_notify_threadsafe)) {
			for(i=0;i<(((uint64_t)datum_config.bitcoind_work_update_seconds*(uint64_t)1000000)/(uint64_t)2500) && !datum_embedded_should_stop();i++) {
				usleep(2500);
				if (new_notify || new_notify_threadsafe) {
					new_notify = 0;
					new_notify_threadsafe = 0;
					was_notified = 1;
					wnc = 0;
					DLOG_INFO("NEW NETWORK BLOCK NOTIFICATION RECEIVED");
					break;
				}
			}
		} else {
			usleep(250000);
			wnc++;
			if (wnc > 16) { // 4 seconds
				// something is weird.
				DLOG_WARN("We received a new block notification, however after 16 attempts we did not see a new block.");
				was_notified = false;
				wnc = 0;
			}
		}
	}
	if (datum_config.bitcoind_notify_fallback) pthread_join(pthread_datum_gateway_fallback_notifier, NULL);
	curl_easy_cleanup(tcurl);
	return NULL;
	// this thread is never intended to exit unless the application dies
	
	// TODO: Clean things up
}
