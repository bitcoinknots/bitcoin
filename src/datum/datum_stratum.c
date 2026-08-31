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

// Stratum V1 server for providing work to mining hardware supporting Stratum V1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <stdatomic.h>
#include <errno.h>
#include <jansson.h>
#include <inttypes.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif

#include "datum_gateway.h"
#include "datum_stratum.h"
#include "datum_stratum_dupes.h"
#include "datum_jsonrpc.h"
#include "datum_utils.h"
#include "datum_blocktemplates.h"
#include "datum_sockets.h"
#include "datum_conf.h"
#include "datum_coinbaser.h"
#include "datum_submitblock.h"
#include "datum_protocol.h"
#include "datum_embedded.h"
#include "datum_thread.h"
#include "datum_time.h"

T_DATUM_SOCKET_APP *global_stratum_app = NULL;
static pthread_mutex_t stratum_app_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t session_stats_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t disconnected_accepted_shares;
static uint64_t disconnected_rejected_shares;
static uint64_t disconnected_last_share_time_ms;
static char last_rejected_share_reason[64];
static uint64_t last_rejected_share_time_ms;
static uint64_t rejected_unknown_work;
static uint64_t rejected_high_hash;
static uint64_t rejected_stale;
static uint64_t rejected_duplicate;
static uint64_t rejected_other;

int stratum_job_next = 0;
T_DATUM_STRATUM_JOB stratum_job_list[MAX_STRATUM_JOBS];

int global_latest_stratum_job_index = -1;
T_DATUM_STRATUM_JOB *global_cur_stratum_jobs[MAX_STRATUM_JOBS] = { 0 };

pthread_rwlock_t stratum_global_job_ptr_lock = PTHREAD_RWLOCK_INITIALIZER;
uint16_t stratum_enprefix = 0;

pthread_rwlock_t stratum_global_latest_empty_stat = PTHREAD_RWLOCK_INITIALIZER;
uint64_t stratum_latest_empty_complete_count = 0;
bool stratum_latest_empty_ready_for_full = 0;
uint64_t stratum_latest_empty_job_index = 0;
uint64_t stratum_latest_empty_sent_count = 0;

pthread_rwlock_t need_coinbaser_rwlocks[MAX_STRATUM_JOBS];
bool need_coinbaser_rwlocks_init_done = false;

#define DATUM_SECURITY_IP_SLOTS 128
#define DATUM_AUTH_FAILURE_LIMIT 5
#define DATUM_AUTH_WINDOW_MS 60000
#define DATUM_AUTH_COOLDOWN_MS 60000
#define DATUM_SUBMIT_CLIENT_RATE 128.0
#define DATUM_SUBMIT_CLIENT_BURST 256.0
#define DATUM_SUBMIT_IP_RATE 512.0
#define DATUM_SUBMIT_IP_BURST 1024.0

typedef struct {
	char ip[DATUM_MAX_IP_LEN + 1];
	uint64_t last_seen_tsms;
	uint64_t auth_window_tsms;
	uint64_t cooldown_until_tsms;
	unsigned int auth_failures;
	double submit_tokens;
	uint64_t submit_tokens_tsms;
} T_DATUM_SECURITY_IP;

static T_DATUM_SECURITY_IP datum_security_ips[DATUM_SECURITY_IP_SLOTS];
static pthread_mutex_t datum_security_lock = PTHREAD_MUTEX_INITIALIZER;

static T_DATUM_SECURITY_IP *datum_security_ip_locked(const char *ip, const uint64_t now)
{
	T_DATUM_SECURITY_IP *oldest = &datum_security_ips[0];
	for (size_t i = 0; i < DATUM_SECURITY_IP_SLOTS; ++i) {
		T_DATUM_SECURITY_IP *entry = &datum_security_ips[i];
		if (entry->ip[0] && !strcmp(entry->ip, ip)) {
			entry->last_seen_tsms = now;
			return entry;
		}
		if (!entry->ip[0]) {
			strncpy(entry->ip, ip, DATUM_MAX_IP_LEN);
			entry->ip[DATUM_MAX_IP_LEN] = 0;
			entry->last_seen_tsms = now;
			entry->submit_tokens = DATUM_SUBMIT_IP_BURST;
			entry->submit_tokens_tsms = now;
			return entry;
		}
		if (entry->last_seen_tsms < oldest->last_seen_tsms) oldest = entry;
	}
	memset(oldest, 0, sizeof(*oldest));
	strncpy(oldest->ip, ip, DATUM_MAX_IP_LEN);
	oldest->ip[DATUM_MAX_IP_LEN] = 0;
	oldest->last_seen_tsms = now;
	oldest->submit_tokens = DATUM_SUBMIT_IP_BURST;
	oldest->submit_tokens_tsms = now;
	return oldest;
}

static bool datum_security_ip_in_cooldown(const char *ip)
{
	const uint64_t now = current_time_millis();
	pthread_mutex_lock(&datum_security_lock);
	T_DATUM_SECURITY_IP *entry = datum_security_ip_locked(ip, now);
	const bool cooldown = entry->cooldown_until_tsms > now;
	pthread_mutex_unlock(&datum_security_lock);
	return cooldown;
}

static void datum_security_auth_failure(const char *ip)
{
	const uint64_t now = current_time_millis();
	pthread_mutex_lock(&datum_security_lock);
	T_DATUM_SECURITY_IP *entry = datum_security_ip_locked(ip, now);
	if (!entry->auth_window_tsms || now - entry->auth_window_tsms >= DATUM_AUTH_WINDOW_MS) {
		entry->auth_window_tsms = now;
		entry->auth_failures = 0;
	}
	if (++entry->auth_failures >= DATUM_AUTH_FAILURE_LIMIT) entry->cooldown_until_tsms = now + DATUM_AUTH_COOLDOWN_MS;
	pthread_mutex_unlock(&datum_security_lock);
}

static bool datum_security_consume_submit(T_DATUM_CLIENT_DATA *c)
{
	T_DATUM_MINER_DATA *m = c->app_client_data;
	const uint64_t now = current_time_millis();
	const uint64_t client_elapsed = now - m->submit_tokens_tsms;
	m->submit_tokens += ((double)client_elapsed * DATUM_SUBMIT_CLIENT_RATE) / 1000.0;
	if (m->submit_tokens > DATUM_SUBMIT_CLIENT_BURST) m->submit_tokens = DATUM_SUBMIT_CLIENT_BURST;
	m->submit_tokens_tsms = now;
	if (m->submit_tokens < 1.0) return false;

	pthread_mutex_lock(&datum_security_lock);
	T_DATUM_SECURITY_IP *entry = datum_security_ip_locked(c->rem_host, now);
	const uint64_t ip_elapsed = now - entry->submit_tokens_tsms;
	entry->submit_tokens += ((double)ip_elapsed * DATUM_SUBMIT_IP_RATE) / 1000.0;
	if (entry->submit_tokens > DATUM_SUBMIT_IP_BURST) entry->submit_tokens = DATUM_SUBMIT_IP_BURST;
	entry->submit_tokens_tsms = now;
	const bool allowed = entry->submit_tokens >= 1.0;
	if (allowed) entry->submit_tokens -= 1.0;
	pthread_mutex_unlock(&datum_security_lock);
	if (!allowed) return false;
	m->submit_tokens -= 1.0;
	return true;
}

void stratum_latest_empty_increment_complete(uint64_t index, int clients_notified) {
	pthread_rwlock_wrlock(&stratum_global_latest_empty_stat);
	if ((stratum_latest_empty_job_index == index) && (!stratum_latest_empty_ready_for_full)) {
		stratum_latest_empty_complete_count++;
		stratum_latest_empty_sent_count += clients_notified;
	}
	pthread_rwlock_unlock(&stratum_global_latest_empty_stat);
}

bool stratum_latest_empty_check_ready_for_full(void) {
	bool a = false;
	pthread_rwlock_rdlock(&stratum_global_latest_empty_stat);
	if (stratum_latest_empty_ready_for_full) {
		a = true;
	}
	pthread_rwlock_unlock(&stratum_global_latest_empty_stat);
	return a;
}

void datum_stratum_v1_shutdown_all(void) {
	int ret;
	unsigned int shutdown_threads = 0;
	pthread_mutex_lock(&stratum_app_lock);
	T_DATUM_SOCKET_APP *app = global_stratum_app;
	if (!app) {
		pthread_mutex_unlock(&stratum_app_lock);
		DLOG_DEBUG("Disconnect request for all stratum clients, but stratum thread is not ready.");
		return;
	}
	for (int tid = 0; tid < app->max_threads; ++tid) {
		if (!app->datum_threads[tid].is_active) continue;
		
		ret = pthread_mutex_lock(&app->datum_threads[tid].thread_data_lock);
		if (ret != 0) {
			pthread_mutex_unlock(&stratum_app_lock);
			DLOG_FATAL("Could not lock mutex for thread data on TID %d: %s", tid, strerror(ret));
			panic_from_thread(__LINE__); // Is this panic worthy? should never happen
			return;
		}
		
		// Send request to gracefully boot all clients from the thread
		app->datum_threads[tid].empty_request = true;
		shutdown_threads++;
		pthread_mutex_unlock(&app->datum_threads[tid].thread_data_lock);
	}
	pthread_mutex_unlock(&stratum_app_lock);
	
	DLOG_INFO("Sent disconnect request for all stratum clients to %u threads.", shutdown_threads);
	return;
}

// Started as its own pthread during startup
void *datum_stratum_v1_socket_server(void *arg) {
	// setup the stratum v1 DATUM socket server
	T_DATUM_SOCKET_APP *app;
	pthread_t pthread_datum_stratum_socket_server;
	int ret;
	int i,j;
#ifndef _WIN32
	struct rlimit rlimit;
#endif
	
	uint64_t ram_allocated = 0;
	
	DLOG_DEBUG("Stratum V1 server startup");
	
	// Setup the socket "app" for Stratum V1
	app = (T_DATUM_SOCKET_APP *)calloc(1,sizeof(T_DATUM_SOCKET_APP));
	if (!app) {
		DLOG_FATAL("Could not allocate memory for Stratum V1 server app metadata! (%lu bytes)", (unsigned long)sizeof(T_DATUM_SOCKET_APP));
		panic_from_thread(__LINE__);
		return NULL;
	}
	ram_allocated += sizeof(T_DATUM_SOCKET_APP);
	
	memset(app, 0, sizeof(T_DATUM_SOCKET_APP));
	
	strcpy(app->name, "Stratum V1 Server");
	
	// setup callbacks
	app->init_func = datum_stratum_v1_socket_thread_init;
	app->loop_func = datum_stratum_v1_socket_thread_loop;
	app->client_cmd_func = datum_stratum_v1_socket_thread_client_cmd;
	app->closed_client_func = datum_stratum_v1_socket_thread_client_closed;
	app->new_client_func = datum_stratum_v1_socket_thread_client_new;
	
	// set listen port
	app->listen_port = datum_config.stratum_v1_listen_port;
	
	// setup limits
	app->max_clients_thread = datum_config.stratum_v1_max_clients_per_thread;
	app->max_threads = datum_config.stratum_v1_max_threads;
	app->max_clients = datum_config.stratum_v1_max_clients;
	
	// Our memory rationale here is to do as few dynamic allocations as possible.
	// We'll also never give up this memory, so no heap fragmentation risk.
	
	// allocate memory for DATUM socket thread data
	app->datum_threads = (T_DATUM_THREAD_DATA *) calloc(app->max_threads + 1, sizeof(T_DATUM_THREAD_DATA));
	if (!app->datum_threads) {
		DLOG_FATAL("Could not allocate memory for Stratum V1 server thread pool data! (%lu bytes)", (unsigned long)(sizeof(T_DATUM_THREAD_DATA) * (app->max_threads + 1)));
		panic_from_thread(__LINE__);
		return NULL;
	}
	ram_allocated += (sizeof(T_DATUM_THREAD_DATA) * (app->max_threads + 1));
	for (i = 0; i < app->max_threads; ++i) {
		app->datum_threads[i].client_data = calloc(app->max_clients_thread, sizeof(T_DATUM_CLIENT_DATA));
		app->datum_threads[i].pollfds = calloc(app->max_clients_thread, sizeof(datum_pollfd));
		app->datum_threads[i].poll_client_ids = calloc(app->max_clients_thread, sizeof(int));
		if (!app->datum_threads[i].client_data || !app->datum_threads[i].pollfds || !app->datum_threads[i].poll_client_ids) {
			DLOG_FATAL("Could not allocate bounded Stratum socket data for thread %d", i);
			panic_from_thread(__LINE__);
			return NULL;
		}
		ram_allocated += app->max_clients_thread * sizeof(T_DATUM_CLIENT_DATA);
		ram_allocated += app->max_clients_thread * sizeof(datum_pollfd);
		ram_allocated += app->max_clients_thread * sizeof(int);
	}
	
	// allocate memory for our per-thread data
	// allocate once for the whole chunk, and set the pointers.  no need to do tons of calls for a static block of data
	app->datum_threads[0].app_thread_data = calloc(app->max_threads + 1, sizeof(T_DATUM_STRATUM_THREADPOOL_DATA));
	if (!app->datum_threads[0].app_thread_data) {
		DLOG_FATAL("Could not allocate memory for Stratum V1 server thread pool app data! (%lu bytes)", (unsigned long)(sizeof(T_DATUM_STRATUM_THREADPOOL_DATA) * (app->max_threads + 1)));
		panic_from_thread(__LINE__);
		return NULL;
	}
	for(i=1;i<app->max_threads;i++) {
		app->datum_threads[i].app_thread_data = &((char *)app->datum_threads[0].app_thread_data)[sizeof(T_DATUM_STRATUM_THREADPOOL_DATA)*i];
	}
	ram_allocated += (sizeof(T_DATUM_STRATUM_THREADPOOL_DATA) * (app->max_threads + 1));
	
	// allocate memory for our per-client data
	// we need to allocate this per thread, since max clients could be lower
	// so our RAM usage will be based on app->max_threads*app->max_clients_thread, sadly, even if this is higher
	// T_DATUM_MINER_DATA
	app->datum_threads[0].client_data[0].app_client_data = calloc(((app->max_threads*app->max_clients_thread)+1), sizeof(T_DATUM_MINER_DATA));
	if (!app->datum_threads[0].client_data[0].app_client_data) {
		DLOG_FATAL("Could not allocate memory for Stratum V1 server per-client data! (%lu bytes)", (unsigned long)(((app->max_threads*app->max_clients_thread)+1) * sizeof(T_DATUM_MINER_DATA)));
		panic_from_thread(__LINE__);
		return NULL;
	}
	ram_allocated += ((app->max_threads*app->max_clients_thread)+1) * sizeof(T_DATUM_MINER_DATA);
	
	for(i=0;i<app->max_threads;i++) {
		for(j=0;j<app->max_clients_thread;j++) {
			if (!((i == 0) && (j == 0))) {
				app->datum_threads[i].client_data[j].app_client_data = &((char *)app->datum_threads[0].client_data[0].app_client_data)[((i*app->max_clients_thread)+j) * sizeof(T_DATUM_MINER_DATA)];
			}
		}
	}
	
	// init locks for each job
	for (i = 0; i < MAX_STRATUM_JOBS; i++) {
		pthread_rwlock_init(&need_coinbaser_rwlocks[i], NULL);
	}
	need_coinbaser_rwlocks_init_done = true;
	
	// Backup thread for submitting blocks found to our node and additional nodes.
	DLOG_DEBUG("Starting submitblock thread");
	datum_submitblock_init();
	
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	i = global_latest_stratum_job_index;
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
	
	// we wait for the block template thread to have work for us before moving on.
	if (i < 0) {
		DLOG_DEBUG("Waiting for our first job before starting listening server...");
		j = 0;
		i = global_latest_stratum_job_index;
		while(i<0 && !datum_embedded_should_stop()) {
			usleep(50000);
			pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
			i = global_latest_stratum_job_index;
			pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
			j++;
			if (j > 500 && j % 100 == 1) {
				DLOG_ERROR("Did not see an initial stratum job after ~%d seconds. Is your node properly setup?", j / 20);
			}
		}
		if (datum_embedded_should_stop()) return NULL;
	}
	
	// start the DATUM socket server
	DLOG_DEBUG("Starting listener thread %p",app);
	ret = pthread_create(&pthread_datum_stratum_socket_server, NULL, datum_gateway_listener_thread, app);
	if (ret != 0) {
		DLOG_FATAL("Could not pthread_create for DATUM socket listener!: %s", strerror(ret));
		panic_from_thread(__LINE__);
		return NULL;
	}
	
	DLOG_INFO("Stratum V1 Server Init complete.");
	DLOG_DEBUG("%"PRIu64" MB of RAM allocated for Stratum V1 server data.", ram_allocated>>20);
	
#ifndef _WIN32
	// TODO: If limits are too low, attempt to set our ulimits in case we're allowed to do so but it hasn't been done before executing.
	if (!getrlimit(RLIMIT_NOFILE, &rlimit)) {
		if (app->max_clients > rlimit.rlim_max) {
			DLOG_WARN("*** NOTE *** Max Stratum clients (%llu) exceeds hard open file limit (Soft: %llu / Hard: %llu)", (unsigned long long)app->max_clients, (unsigned long long)rlimit.rlim_cur, (unsigned long long)rlimit.rlim_max);
			DLOG_WARN("*** NOTE *** Adjust max open file hard limit or you WILL run into issues before reaching max clients!");
		} else if (app->max_clients > rlimit.rlim_cur) {
			DLOG_WARN("*** NOTE *** Max Stratum clients (%llu) exceeds open file soft limit (Soft: %llu / Hard: %llu)", (unsigned long long)app->max_clients, (unsigned long long)rlimit.rlim_cur, (unsigned long long)rlimit.rlim_max);
			DLOG_WARN("*** NOTE *** You should increase the soft open file limit to prevent issues as you approach max clients!");
		}
	}
#endif
	
	pthread_mutex_lock(&stratum_app_lock);
	global_stratum_app = app;
	pthread_mutex_unlock(&stratum_app_lock);
	
	while (!datum_embedded_should_stop()) {
		// do periodic global stratum things here
		
		// If we're on an empty block waiting for a full one, handle that state transition here.
		pthread_rwlock_wrlock(&stratum_global_latest_empty_stat);
		if (!stratum_latest_empty_ready_for_full) {
			// we're still on an empty wait-for-full
			if (stratum_latest_empty_complete_count >= app->datum_active_threads) {
				// we are done!
				stratum_latest_empty_ready_for_full = true;
				DLOG_INFO("Empty work send completed. Sent to %llu clients across %llu threads", (unsigned long long)stratum_latest_empty_sent_count, (unsigned long long)stratum_latest_empty_complete_count);
			}
		}
		pthread_rwlock_unlock(&stratum_global_latest_empty_stat);
		
		usleep(11000);
	}
	pthread_join(pthread_datum_stratum_socket_server, NULL);
	for (i = 0; i < app->max_threads; ++i) {
		if (app->datum_threads[i].is_active) pthread_join(app->datum_threads[i].pthread, NULL);
	}
	pthread_mutex_lock(&stratum_app_lock);
	global_stratum_app = NULL;
	free(app->datum_threads[0].client_data[0].app_client_data);
	free(app->datum_threads[0].app_thread_data);
	for (i = 0; i < app->max_threads; ++i) {
		free(app->datum_threads[i].poll_client_ids);
		free(app->datum_threads[i].pollfds);
		free(app->datum_threads[i].client_data);
	}
	free(app->datum_threads);
	free(app);
	pthread_mutex_unlock(&stratum_app_lock);
	
	return NULL;
}

int datum_stratum_v1_global_subscriber_count(void) {
	int j, kk, ii;
	T_DATUM_MINER_DATA *m;
	
	pthread_mutex_lock(&stratum_app_lock);
	T_DATUM_SOCKET_APP *app = global_stratum_app;
	if (!app) {
		pthread_mutex_unlock(&stratum_app_lock);
		return 0;
	}
	
	kk = 0;
	for(j=0;j<app->max_threads;j++) {
		for(ii=0;ii<app->max_clients_thread;ii++) {
			if (app->datum_threads[j].client_data[ii].fd > 0) {
				m = app->datum_threads[j].client_data[ii].app_client_data;
				if (m->subscribed && m->authorized) kk++;
			}
		}
	}
	pthread_mutex_unlock(&stratum_app_lock);
	
	return kk;
}

void datum_stratum_v1_get_stats(uint32_t *clients, uint32_t *authorized_clients,
	uint64_t *accepted_shares, uint64_t *rejected_shares, uint64_t *current_height)
{
	if (clients) *clients = 0;
	if (authorized_clients) *authorized_clients = 0;
	if (accepted_shares) *accepted_shares = 0;
	if (rejected_shares) *rejected_shares = 0;
	if (current_height) *current_height = 0;
	pthread_mutex_lock(&stratum_app_lock);
	T_DATUM_SOCKET_APP *app = global_stratum_app;
	if (!app) {
		pthread_mutex_unlock(&stratum_app_lock);
		return;
	}
	for (int tid = 0; tid < app->max_threads; ++tid) {
		pthread_mutex_lock(&app->datum_threads[tid].thread_data_lock);
		for (int cid = 0; cid < app->max_clients_thread; ++cid) {
			if (app->datum_threads[tid].client_data[cid].fd <= 0) continue;
			T_DATUM_MINER_DATA *m = app->datum_threads[tid].client_data[cid].app_client_data;
			if (clients) ++*clients;
			if (authorized_clients && m->authorized) ++*authorized_clients;
			if (accepted_shares) *accepted_shares += m->share_count_accepted;
			if (rejected_shares) *rejected_shares += m->share_count_rejected;
		}
		pthread_mutex_unlock(&app->datum_threads[tid].thread_data_lock);
	}
	pthread_mutex_unlock(&stratum_app_lock);
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	if (current_height && global_latest_stratum_job_index >= 0 && global_cur_stratum_jobs[global_latest_stratum_job_index]) {
		*current_height = global_cur_stratum_jobs[global_latest_stratum_job_index]->height;
	}
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
}

static double datum_miner_est_th_sec(const T_DATUM_MINER_DATA *m, uint64_t now_ms)
{
	const unsigned char index = atomic_load_explicit(&m->stats.active_index, memory_order_relaxed) ? 0 : 1;
	const uint64_t elapsed_ms = atomic_load_explicit(&m->stats.last_swap_ms, memory_order_relaxed);
	const uint64_t swap_ms = atomic_load_explicit(&m->stats.last_swap_tsms, memory_order_relaxed);
	const uint64_t accepted_diff = atomic_load_explicit(&m->stats.diff_accepted[index], memory_order_relaxed);
	if (!elapsed_ms || !accepted_diff || now_ms - swap_ms >= 180000) return 0.0;
	return ((double)accepted_diff / ((double)elapsed_ms / 1000.0)) * 0.004294967296;
}

void datum_stratum_v1_reset_session_stats(void)
{
	pthread_mutex_lock(&session_stats_lock);
	disconnected_accepted_shares = 0;
	disconnected_rejected_shares = 0;
	disconnected_last_share_time_ms = 0;
	last_rejected_share_reason[0] = '\0';
	last_rejected_share_time_ms = 0;
	rejected_unknown_work = 0;
	rejected_high_hash = 0;
	rejected_stale = 0;
	rejected_duplicate = 0;
	rejected_other = 0;
	pthread_mutex_unlock(&session_stats_lock);
}

void datum_stratum_v1_get_extended_stats(datum_embedded_stats *stats)
{
	if (!stats) return;
	const uint64_t now_ms = current_time_millis();
	pthread_mutex_lock(&session_stats_lock);
	stats->session_accepted_shares = disconnected_accepted_shares;
	stats->session_rejected_shares = disconnected_rejected_shares;
	stats->last_share_time_ms = disconnected_last_share_time_ms;
	stats->last_rejected_share_time_ms = last_rejected_share_time_ms;
	stats->rejected_unknown_work = rejected_unknown_work;
	stats->rejected_high_hash = rejected_high_hash;
	stats->rejected_stale = rejected_stale;
	stats->rejected_duplicate = rejected_duplicate;
	stats->rejected_other = rejected_other;
	strncpy(stats->last_rejected_share_reason, last_rejected_share_reason, sizeof(stats->last_rejected_share_reason) - 1);

	pthread_mutex_lock(&stratum_app_lock);
	T_DATUM_SOCKET_APP *app = global_stratum_app;
	if (app) {
		for (int tid = 0; tid < app->max_threads; ++tid) {
			pthread_mutex_lock(&app->datum_threads[tid].thread_data_lock);
			for (int cid = 0; cid < app->max_clients_thread; ++cid) {
				if (app->datum_threads[tid].client_data[cid].fd <= 0) continue;
				T_DATUM_MINER_DATA *m = app->datum_threads[tid].client_data[cid].app_client_data;
				++stats->clients;
				if (atomic_load_explicit(&m->subscribed, memory_order_relaxed)) ++stats->subscribed_clients;
				if (atomic_load_explicit(&m->authorized, memory_order_relaxed)) ++stats->authorized_clients;
				const uint64_t accepted = atomic_load_explicit(&m->share_count_accepted, memory_order_relaxed);
				const uint64_t rejected = atomic_load_explicit(&m->share_count_rejected, memory_order_relaxed);
				stats->accepted_shares += accepted;
				stats->rejected_shares += rejected;
				stats->session_accepted_shares += accepted;
				stats->session_rejected_shares += rejected;
				const uint64_t last_share = atomic_load_explicit(&m->stats.last_share_tsms, memory_order_relaxed);
				if (last_share > stats->last_share_time_ms) stats->last_share_time_ms = last_share;
				stats->estimated_hashrate_ths += datum_miner_est_th_sec(m, now_ms);
			}
			pthread_mutex_unlock(&app->datum_threads[tid].thread_data_lock);
		}
	}
	pthread_mutex_unlock(&stratum_app_lock);
	pthread_mutex_unlock(&session_stats_lock);

	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	if (global_latest_stratum_job_index >= 0 && global_cur_stratum_jobs[global_latest_stratum_job_index]) {
		const T_DATUM_STRATUM_JOB *job = global_cur_stratum_jobs[global_latest_stratum_job_index];
		stats->current_height = job->height;
		stats->job_created_ms = job->tsms;
		stats->nbits = job->nbits_uint;
		stats->coinbase_value = job->coinbase_value;
		strncpy(stats->job_id, job->job_id, sizeof(stats->job_id) - 1);
		if (job->block_template) {
			strncpy(stats->previous_block_hash, job->block_template->previousblockhash, sizeof(stats->previous_block_hash) - 1);
			stats->transaction_count = job->block_template->txn_count;
			stats->template_size = job->block_template->txn_total_size;
			stats->template_weight = job->block_template->txn_total_weight;
		}
	}
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
}

uint32_t datum_stratum_v1_get_miner_stats(datum_embedded_miner_stats *miners, uint32_t capacity)
{
	if (!miners || !capacity) return 0;
	uint32_t count = 0;
	const uint64_t now_ms = current_time_millis();
	pthread_mutex_lock(&stratum_app_lock);
	T_DATUM_SOCKET_APP *app = global_stratum_app;
	if (app) {
		for (int tid = 0; tid < app->max_threads && count < capacity; ++tid) {
			pthread_mutex_lock(&app->datum_threads[tid].thread_data_lock);
			for (int cid = 0; cid < app->max_clients_thread && count < capacity; ++cid) {
				T_DATUM_CLIENT_DATA *client = &app->datum_threads[tid].client_data[cid];
				if (client->fd <= 0) continue;
				T_DATUM_MINER_DATA *m = client->app_client_data;
				datum_embedded_miner_stats *out = &miners[count++];
				memset(out, 0, sizeof(*out));
				strncpy(out->worker, m->last_auth_username, sizeof(out->worker) - 1);
				strncpy(out->remote_host, client->rem_host, sizeof(out->remote_host) - 1);
				strncpy(out->user_agent, m->useragent, sizeof(out->user_agent) - 1);
				out->subscribed = atomic_load_explicit(&m->subscribed, memory_order_relaxed);
				out->authorized = atomic_load_explicit(&m->authorized, memory_order_relaxed);
				out->connected_since_ms = m->connect_tsms;
				out->current_difficulty = m->current_diff;
				out->estimated_hashrate_ths = datum_miner_est_th_sec(m, now_ms);
				out->accepted_shares = atomic_load_explicit(&m->share_count_accepted, memory_order_relaxed);
				out->rejected_shares = atomic_load_explicit(&m->share_count_rejected, memory_order_relaxed);
				out->last_share_time_ms = atomic_load_explicit(&m->stats.last_share_tsms, memory_order_relaxed);
			}
			pthread_mutex_unlock(&app->datum_threads[tid].thread_data_lock);
		}
	}
	pthread_mutex_unlock(&stratum_app_lock);
	return count;
}

// TODO: Make this more accurate by tracking work over a longer period of time per user
double datum_stratum_v1_est_total_th_sec(void) {
	double hr;
	unsigned char astat;
	double thr = 0.0;
	T_DATUM_MINER_DATA *m = NULL;
	uint64_t tsms;
	int j,ii;
	
	pthread_mutex_lock(&stratum_app_lock);
	T_DATUM_SOCKET_APP *app = global_stratum_app;
	if (!app) {
		pthread_mutex_unlock(&stratum_app_lock);
		return 0;
	}
	
	tsms = current_time_millis();
	
	for(j=0;j<app->max_threads;j++) {
		for(ii=0;ii<app->max_clients_thread;ii++) {
			if (app->datum_threads[j].client_data[ii].fd > 0) {
				m = app->datum_threads[j].client_data[ii].app_client_data;
				if (m->subscribed && m->authorized) {
					astat = m->stats.active_index?0:1; // inverted
					hr = 0.0;
					if ((m->stats.last_swap_ms > 0) && (m->stats.diff_accepted[astat] > 0)) {
						hr = ((double)m->stats.diff_accepted[astat] / (double)((double)m->stats.last_swap_ms/1000.0)) * 0.004294967296; // Th/sec based on shares/sec
					}
					if (((double)(tsms - m->stats.last_swap_tsms)/1000.0) < 180.0) {
						thr += hr;
					}
				}
			}
		}
	}
	pthread_mutex_unlock(&stratum_app_lock);
	
	return thr;
}

void datum_stratum_v1_socket_thread_client_closed(T_DATUM_CLIENT_DATA *c, const char *msg) {
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	pthread_mutex_lock(&session_stats_lock);
	disconnected_accepted_shares += atomic_load_explicit(&m->share_count_accepted, memory_order_relaxed);
	disconnected_rejected_shares += atomic_load_explicit(&m->share_count_rejected, memory_order_relaxed);
	const uint64_t last_share = atomic_load_explicit(&m->stats.last_share_tsms, memory_order_relaxed);
	if (last_share > disconnected_last_share_time_ms) disconnected_last_share_time_ms = last_share;
	pthread_mutex_unlock(&session_stats_lock);
	DLOG_DEBUG("Stratum client connection closed. (%s)", msg);
}

void datum_stratum_v1_socket_thread_client_new(T_DATUM_CLIENT_DATA *c) {
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	
	DLOG_DEBUG("New Stratum client connected. %" PRIuPTR, (uintptr_t)c->fd);
	
	// clear miner data for connection
	memset(m, 0, sizeof(T_DATUM_MINER_DATA));
	m->sdata = (T_DATUM_STRATUM_THREADPOOL_DATA *)c->datum_thread->app_thread_data;
	m->stats.last_swap_tsms = m->stats.last_share_tsms;
	m->authorized = !datum_config.stratum_v1_auth_required;
	m->submit_tokens = DATUM_SUBMIT_CLIENT_BURST;
	m->submit_tokens_tsms = current_time_millis();
	
	static atomic_uint_fast64_t unique_id_ctr;
	m->unique_id = atomic_fetch_add_explicit(&unique_id_ctr, 1, memory_order_relaxed);
	
	// set initial connection time
	// if this is the first client on the thread, we won't have a loop_tsms yet
	if (m->sdata->loop_tsms > 0) {
		m->connect_tsms = m->sdata->loop_tsms;
	} else {
		m->connect_tsms = current_time_millis();
	}
	if (datum_security_ip_in_cooldown(c->rem_host)) {
		c->kill_request = true;
		c->datum_thread->has_client_kill_request = true;
	}
}

void datum_stratum_v1_socket_thread_init(T_DATUM_THREAD_DATA *my) {
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = (T_DATUM_STRATUM_THREADPOOL_DATA *)my->app_thread_data;
	
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	sdata->latest_stratum_job_index = global_latest_stratum_job_index;
	sdata->cur_stratum_job = global_cur_stratum_jobs[global_latest_stratum_job_index];
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
	sdata->new_job = false;
	sdata->last_sent_job_state = 0;
	
	sdata->next_kick_check_tsms = current_time_millis() + 1000;
	
	sdata->share_difficulty_seen = datum_embedded_get_share_difficulty();

	// initialize the dupe checker system
	datum_stratum_dupes_init(sdata);
}

int datum_stratum_v1_get_thread_subscriber_count(T_DATUM_THREAD_DATA *my) {
	int i,c=0;
	T_DATUM_MINER_DATA *m;
	
	for(i=0;i<my->app->max_clients_thread;i++) {
		m = my->client_data[i].app_client_data;
		if (my->client_data[i].fd && m->subscribed && m->authorized) {
			c++;
		}
	}
	return c;
}

bool stratum_job_coinbaser_ready(T_DATUM_STRATUM_THREADPOOL_DATA *sdata, T_DATUM_STRATUM_JOB *job) {
	bool a = false;
	// backup timeout for coinbaser on these jobs
	if ((sdata->loop_tsms > job->tsms) && (sdata->loop_tsms - job->tsms) > 5000) {
		// enforce a timeout of 5 seconds on waiting on a coinbaser...
		sdata->full_coinbase_ready = false;
		return true;
	}
	
	pthread_rwlock_rdlock(&need_coinbaser_rwlocks[job->global_index]);
	if (!job->need_coinbaser) {
		a = true;
	}
	pthread_rwlock_unlock(&need_coinbaser_rwlocks[job->global_index]);
	
	if (a) {
		sdata->full_coinbase_ready = true;
	}
	
	return a;
}

void datum_stratum_v1_socket_thread_loop(T_DATUM_THREAD_DATA *my) {
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = (T_DATUM_STRATUM_THREADPOOL_DATA *)my->app_thread_data;
	T_DATUM_STRATUM_JOB *job = NULL;
	T_DATUM_MINER_DATA *m = NULL;
	int i;
	bool change_ready = true;
	bool difficulty_broadcasted = false;
	int cnt = 0;
	uint64_t tsms,tsms2,tsms3;
	const uint64_t share_difficulty = datum_embedded_get_share_difficulty();
	const bool difficulty_changed = share_difficulty > 0 && share_difficulty != sdata->share_difficulty_seen;
	if (difficulty_changed) sdata->share_difficulty_seen = share_difficulty;
	
	// check if the stratum job has been updated
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	if (global_latest_stratum_job_index != sdata->latest_stratum_job_index) {
		change_ready = true;
		if ((sdata->last_was_empty) && (global_cur_stratum_jobs[global_latest_stratum_job_index]->job_state >= JOB_STATE_FULL_PRIORITY_WAIT_COINBASER)) {
			// we went from an empty to a coinbaser wait job somehow...
			// we don't want to delay our full work blast, however...
			if (!stratum_job_coinbaser_ready(sdata,global_cur_stratum_jobs[global_latest_stratum_job_index])) {
				// yeah, it's not ready.  let's just pretend we didn't see this job yet...
				// ... unless it's a different block height and we're somehow _that_ far behind on processing.
				// should never happen, but let's be careful.
				if (sdata->last_job_height == global_cur_stratum_jobs[global_latest_stratum_job_index]->height) {
					change_ready = false;
				}
			}
		}
		
		if (change_ready) {
			sdata->cur_stratum_job = global_cur_stratum_jobs[global_latest_stratum_job_index];
			sdata->latest_stratum_job_index = global_latest_stratum_job_index;
			sdata->new_job = true;
			
			if (sdata->cur_stratum_job->job_state == 2) {
				// make sure we dont skip our empty work if job type 2
				sdata->last_was_empty = false;
			}
			sdata->notify_remaining_count = 0; // this is new work
			sdata->full_coinbase_ready = false;
			sdata->last_job_height = sdata->cur_stratum_job->height;
		}
	}
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
	
	sdata->loop_tsms = current_time_millis();
	
	job = sdata->cur_stratum_job;
	if (sdata->new_job) {
		switch (job->job_state) {
			case 1: {
				// this is an empty work job.  it should be followed up by a full priority job
				sdata->full_coinbase_ready = false;
				DLOG_DEBUG("Blasting empty work type 1 for thread %d",my->thread_id);
				for(i=0;i<my->app->max_clients_thread;i++) {
					m = my->client_data[i].app_client_data;
					if (my->client_data[i].fd && m->subscribed && m->authorized) {
						send_mining_notify(&my->client_data[i],true,false,true);
						cnt++;
					}
				}
				
					sdata->new_job = false; // we're waiting on a completely new job for the next blast wave
					sdata->last_was_empty = true;
					difficulty_broadcasted = true;
					stratum_latest_empty_increment_complete(sdata->latest_stratum_job_index, cnt); // we do want to make sure everyone got an empty before a full still
				sdata->last_sent_job_state = 1;
				break;
			}
			
			case 2: {
				sdata->full_coinbase_ready = false;
				// this is an empty+ job.  blast the empty work the first time around
				if (!sdata->last_was_empty) {
					// blast empty
					DLOG_DEBUG("Blasting empty work type 2 for thread %d",my->thread_id);
					for(i=0;i<my->app->max_clients_thread;i++) {
						m = my->client_data[i].app_client_data;
						if (my->client_data[i].fd && m->subscribed && m->authorized) {
							send_mining_notify(&my->client_data[i],true,false,true);
							cnt++;
						}
					}
					
						sdata->last_was_empty = true;
						difficulty_broadcasted = true;
						stratum_latest_empty_increment_complete(sdata->latest_stratum_job_index, cnt);
					sdata->last_sent_job_state = 2;
					break;
				} else {
					if (stratum_latest_empty_check_ready_for_full()) {
						// blast full when all threads ready or timed out
						DLOG_DEBUG("Blasting full work for type 2 job thread %d",my->thread_id);
						for(i=0;i<my->app->max_clients_thread;i++) {
							m = my->client_data[i].app_client_data;
							if (my->client_data[i].fd && m->subscribed && m->authorized) {
								send_mining_notify(&my->client_data[i],false,false,false);
							}
						}
						
						sdata->new_job = false;
						sdata->last_was_empty = false;
						difficulty_broadcasted = true;
						sdata->last_sent_job_state = 2; // probably should be different, but not sure if needed.
					}
				}
				break;
			}
			
			case 3: {
				// This is a full work job, no coinbaser wait, and has priority blasting
				// it's possible this job gets skipped straight to 4
				sdata->full_coinbase_ready = false;
				DLOG_DEBUG("Blasting full work for type 3 job thread %d",my->thread_id);
				for(i=0;i<my->app->max_clients_thread;i++) {
					m = my->client_data[i].app_client_data;
					if (my->client_data[i].fd && m->subscribed && m->authorized) {
						send_mining_notify(&my->client_data[i],false,false,false);
					}
				}
				
				sdata->new_job = false;
				sdata->last_was_empty = false;
				difficulty_broadcasted = true;
				sdata->last_sent_job_state = 3;
				break;
			}
			
			case 4: {
				// this is a full work job with blast priority once we get our coinbaser
				// the coinbaser readiness needs to hide behind a lock specific to the job
				sdata->full_coinbase_ready = false;
				if (stratum_job_coinbaser_ready(sdata,job)) { // will set sdata->full_coinbase_ready = true if it's really ready.  if it times out, it will not.
					DLOG_DEBUG("Blasting full work for type 4 job thread %d",my->thread_id);
					for(i=0;i<my->app->max_clients_thread;i++) {
						m = my->client_data[i].app_client_data;
						if (my->client_data[i].fd && m->subscribed && m->authorized) {
							send_mining_notify(&my->client_data[i],false,false,false);
						}
					}
					
					sdata->new_job = false;
					sdata->last_was_empty = false;
					difficulty_broadcasted = true;
					sdata->last_sent_job_state = 4;
				}
				break;
			}
			
			case 5: {
				sdata->full_coinbase_ready = false;
				if (stratum_job_coinbaser_ready(sdata,job)) {
					// this is a normal job that normally gets slowly sent out over the course of the work change time until interupted by a new block
					if (sdata->last_was_empty) {
						// HOWEVER...
						// if the last work this thread sent out was empty work, likely due to load or whatever
						// then we don't want to delay the sending of full work.
						// up until this point, this wasn't a concern, but it could be if load is high and the socket side processing
						// takes a long time
						// blast out the work NOW
						DLOG_DEBUG("Blasting full work for type 5 job thread %d",my->thread_id);
						for(i=0;i<my->app->max_clients_thread;i++) {
							m = my->client_data[i].app_client_data;
							if (my->client_data[i].fd && m->subscribed && m->authorized) {
								send_mining_notify(&my->client_data[i],false,false,false);
							}
						}
						difficulty_broadcasted = true;
					} else {
						// last work was not empty, so we can safely slow things up a bit.
						sdata->notify_remaining_count = datum_stratum_v1_get_thread_subscriber_count(my);
						
						if (sdata->notify_remaining_count > 0) {
							sdata->notify_last_cid = -1;
							sdata->notify_start_time = sdata->loop_tsms;
							sdata->notify_delay_per_slot_tsms = ((datum_config.bitcoind_work_update_seconds - 3)*1000) / sdata->notify_remaining_count;
							if (!sdata->notify_delay_per_slot_tsms) {
								sdata->notify_delay_per_slot_tsms = 1;
							}
							
							// loosely stagger based on thread ID as well
							sdata->notify_last_time = sdata->loop_tsms - ((sdata->notify_delay_per_slot_tsms / my->app->max_threads) * my->thread_id);
							DLOG_DEBUG("Pacing job update for thread %d to %d clients @ %"PRIu64" ms",my->thread_id, sdata->notify_remaining_count, sdata->notify_delay_per_slot_tsms);
						}
					}
					sdata->new_job = false;
					sdata->last_was_empty = false;
					sdata->last_sent_job_state = 5; // technically might not be "sent" yet, but last processed for sure.
				}
				break;
			}
			
			case 0:
			default: {
				// Unknown job state...
				break;
			}
		}
	}

	if (difficulty_changed && !difficulty_broadcasted && job) {
		sdata->notify_remaining_count = 0;
		for (i = 0; i < my->app->max_clients_thread; ++i) {
			m = my->client_data[i].app_client_data;
			if (my->client_data[i].fd && m->subscribed && m->authorized) {
				m->current_diff = share_difficulty;
				send_mining_notify(&my->client_data[i], true, false, false);
			}
		}
	}
	
	// slowly send out non-critical work changes
	// this prevents bandwidth spikes from the server sending notifies to all clients at once.
	// that would be quite wasteful and hard on remote connections.
	if (sdata->notify_remaining_count > 0) {
		// we have notifies to send
		tsms = sdata->loop_tsms - sdata->notify_last_time;
		
		if ((!tsms) || (tsms >= sdata->notify_delay_per_slot_tsms)) {
			tsms = tsms / sdata->notify_delay_per_slot_tsms;
			if (!tsms) tsms = 1;
			
			for(i=(sdata->notify_last_cid+1);i<my->app->max_clients_thread;i++) {
				m = my->client_data[i].app_client_data;
				if (my->client_data[i].fd && m->subscribed && m->authorized && m->subscribe_tsms <= sdata->notify_start_time) {
					send_mining_notify(&my->client_data[i],false,false,false);
					sdata->notify_remaining_count--;
					sdata->notify_last_cid = i;
					tsms--;
					if (!tsms) break;
				}
			}
			if (i==my->app->max_clients_thread) {
				sdata->notify_remaining_count = 0;
			}
			sdata->notify_last_time = sdata->loop_tsms;
		}
	}
	
	if (sdata->loop_tsms >= sdata->next_kick_check_tsms) {
		if ((datum_config.stratum_v1_idle_timeout_no_subscribe > 0) || (datum_config.stratum_v1_idle_timeout_no_share > 0) || (datum_config.stratum_v1_idle_timeout_max_last_work)) {
			tsms = 1;
			tsms2 = 1;
			tsms3 = 1;
			if (datum_config.stratum_v1_idle_timeout_no_subscribe > 0) {
				tsms = sdata->loop_tsms - (datum_config.stratum_v1_idle_timeout_no_subscribe * 1000);
			}
			
			if (datum_config.stratum_v1_idle_timeout_no_share > 0) {
				tsms2 = sdata->loop_tsms - (datum_config.stratum_v1_idle_timeout_no_share * 1000);
			}
			
			if (datum_config.stratum_v1_idle_timeout_max_last_work > 0) {
				tsms3 = sdata->loop_tsms - (datum_config.stratum_v1_idle_timeout_max_last_work * 1000);
			}
			
			for(i=0;i<my->app->max_clients_thread;i++) {
				if (my->client_data[i].fd) {
					m = my->client_data[i].app_client_data;
					if (datum_config.stratum_v1_auth_required && !m->authorized &&
						m->connect_tsms + ((uint64_t)datum_config.stratum_v1_auth_timeout_seconds * 1000) <= sdata->loop_tsms) {
						DLOG_WARN("Authentication timeout from %s", my->client_data[i].rem_host);
						my->client_data[i].kill_request = true;
						my->has_client_kill_request = true;
						continue;
					}
					if (m->subscribed && m->authorized) {
						// subscribed
						if (m->share_count_accepted > 0) {
							// has accepted shares
							if (m->stats.last_share_tsms < tsms3) {
								DLOG_DEBUG("Kicking client %d/%d (%s) for being idle > %d seconds without submitting any new shares. (connected %.2f, currently %.2f, delta %.2f)",my->thread_id, i, my->client_data[i].rem_host, datum_config.stratum_v1_idle_timeout_max_last_work, (double)m->connect_tsms / (double)1000.0, (double)sdata->loop_tsms/ (double)1000.0, (double)(sdata->loop_tsms - m->connect_tsms) / (double)1000.0);
								// boot them!
								my->client_data[i].kill_request = true;
								my->has_client_kill_request = true;
							}
						} else {
							// no accepted shares
							if (m->connect_tsms < tsms2) {
								DLOG_DEBUG("Kicking client %d/%d (%s) for being idle > %d seconds without submitting any shares. (connected %.2f, currently %.2f, delta %.2f)",my->thread_id, i, my->client_data[i].rem_host, datum_config.stratum_v1_idle_timeout_no_share, (double)m->connect_tsms / (double)1000.0, (double)sdata->loop_tsms/ (double)1000.0, (double)(sdata->loop_tsms - m->connect_tsms) / (double)1000.0);
								// boot them!
								my->client_data[i].kill_request = true;
								my->has_client_kill_request = true;
							}
						}
					} else {
						// not subscribed
						if (m->connect_tsms < tsms) {
							// boot them!
							DLOG_DEBUG("Kicking client %d/%d (%s) for being idle > %d seconds without subscribing. (connected %.2f, currently %.2f, delta %.2f)",my->thread_id, i, my->client_data[i].rem_host, datum_config.stratum_v1_idle_timeout_no_subscribe, (double)m->connect_tsms / (double)1000.0, (double)sdata->loop_tsms/ (double)1000.0, (double)(sdata->loop_tsms - m->connect_tsms) / (double)1000.0);
							my->client_data[i].kill_request = true;
							my->has_client_kill_request = true;
						}
					}
				}
			}
		}
		
		sdata->next_kick_check_tsms = sdata->loop_tsms + 1000;
	}
}

void send_error_to_client(T_DATUM_CLIENT_DATA *c, uint64_t id, char *e) {
	// "e" must be valid JSON string
	char s[1024];
	snprintf(s, sizeof(s), "{\"error\":%s,\"id\":%"PRIu64",\"result\":null}\n", e, id);
	datum_socket_send_string_to_client(c, s);
}

static inline void log_rejected_share(T_DATUM_CLIENT_DATA *c, const char *reason) {
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	pthread_mutex_lock(&session_stats_lock);
	strncpy(last_rejected_share_reason, reason, sizeof(last_rejected_share_reason) - 1);
	last_rejected_share_reason[sizeof(last_rejected_share_reason) - 1] = '\0';
	last_rejected_share_time_ms = current_time_millis();
	if (!strcmp(reason, "unknown-work")) ++rejected_unknown_work;
	else if (!strcmp(reason, "high-hash") || !strcmp(reason, "H-not-zero")) ++rejected_high_hash;
	else if (!strcmp(reason, "stale-work") || !strcmp(reason, "stale-prevblk")) ++rejected_stale;
	else if (!strcmp(reason, "duplicate")) ++rejected_duplicate;
	else ++rejected_other;
	pthread_mutex_unlock(&session_stats_lock);
	if ((m->share_count_rejected == 0) || ((m->share_count_rejected & 1023) == 0)) {
		DLOG_INFO("Stratum share rejected: worker=%s reason=%s rejected=%"PRIu64,
			m->last_auth_username[0] ? m->last_auth_username : "unknown",
			reason, m->share_count_rejected + 1);
	}
}

static inline void send_unknown_work_error(T_DATUM_CLIENT_DATA *c, uint64_t id) {
	log_rejected_share(c, "unknown-work");
	send_error_to_client(c, id, "[20,\"unknown-work\",null]");
}

static inline void send_rejected_high_hash_error(T_DATUM_CLIENT_DATA *c, uint64_t id) {
	log_rejected_share(c, "high-hash");
	send_error_to_client(c, id, "[23,\"high-hash\",null]");
}

static inline void send_rejected_stale(T_DATUM_CLIENT_DATA *c, uint64_t id) {
	log_rejected_share(c, "stale-work");
	send_error_to_client(c, id, "[21,\"stale-work\",null]");
}

static inline void send_rejected_time_too_old(T_DATUM_CLIENT_DATA *c, uint64_t id) {
	log_rejected_share(c, "time-too-old");
	send_error_to_client(c, id, "[21,\"time-too-old\",null]");
}

static inline void send_rejected_time_too_new(T_DATUM_CLIENT_DATA *c, uint64_t id) {
	log_rejected_share(c, "time-too-new");
	send_error_to_client(c, id, "[21,\"time-too-new\",null]");
}

static inline void send_rejected_stale_block(T_DATUM_CLIENT_DATA *c, uint64_t id) {
	log_rejected_share(c, "stale-prevblk");
	send_error_to_client(c, id, "[21,\"stale-prevblk\",null]");
}

static inline void send_rejected_hnotzero_error(T_DATUM_CLIENT_DATA *c, uint64_t id) {
	log_rejected_share(c, "H-not-zero");
	send_error_to_client(c, id, "[23,\"H-not-zero\",null]");
}

static inline void send_bad_version_error(T_DATUM_CLIENT_DATA *c, uint64_t id) {
	log_rejected_share(c, "bad-version");
	send_error_to_client(c, id, "[23,\"bad-version\",null]");
}

static inline void send_rejected_duplicate(T_DATUM_CLIENT_DATA *c, uint64_t id) {
	log_rejected_share(c, "duplicate");
	send_error_to_client(c, id, "[22,\"duplicate\",null]");
}

uint32_t get_new_session_id(T_DATUM_CLIENT_DATA *c) {
	// K.I.S.S. --- Session ID is just the thread ID and client ID, XOR with our constant.
	// This will always be unique for every client connected to the server.
	// We end up "limited" a little, but sanely:
	// --- Max threads: 1,024
	// --- Max clients per thread: 4,194,304
	//
	// Downside to this is it prevents stratum v1 resume, however almost nothing appears to implement this correctly anymore anyway
	// TODO: Potentially implement stratum resume if a requested session ID is unique and available
	
	uint32_t i;
	
	i = ((uint32_t)c->cid) & (uint32_t)0x003FFFFF;
	i |= ((((uint32_t)c->datum_thread->thread_id)<<22) & (uint32_t)0xFFC00000);
	
	return i ^ 0xB10CF00D; // Feed us the blocks.
}

void reset_vardiff_stats(T_DATUM_CLIENT_DATA *c) {
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	m->share_count_since_snap = 0;
	m->share_diff_since_snap = 0;
	m->share_snap_tsms = m->sdata->loop_tsms;
}

void stratum_update_vardiff(T_DATUM_CLIENT_DATA *c, bool no_quick) {
	// Should be called at/around a share being accepted?
	// before processing a mining notify? (for downward
	
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	if (datum_config.stratum_v1_fixed_difficulty) {
		const uint64_t difficulty = datum_embedded_get_share_difficulty();
		m->current_diff = difficulty ? difficulty : datum_config.stratum_v1_vardiff_min;
		return;
	}
	uint64_t delta_tsms;
	uint64_t ms_per_share;
	uint64_t target_ms_share;
	
	// if we already have a diff change pending, don't do calcs again
	if (m->current_diff != m->last_sent_diff) return;
	
	// don't even bother until we have at least X shares to work with for quick diff
	if ((!no_quick) && (m->share_count_since_snap < datum_config.stratum_v1_vardiff_quickdiff_count)) {
		return;
	}
	
	delta_tsms = m->sdata->loop_tsms - m->share_snap_tsms;
	
	if (!m->share_count_since_snap) {
		// no shares since last snap
		// is it because our diff is way too high?
		if (delta_tsms > 60000) {
			// 60s with no shares seems sufficient to bump diff down next round.
			m->current_diff = m->current_diff >> 1;
			if (m->current_diff < m->forced_high_min_diff) {
				m->current_diff = m->forced_high_min_diff;
			}
			if (m->current_diff < datum_config.stratum_v1_vardiff_min) {
				m->current_diff = datum_config.stratum_v1_vardiff_min;
			}
			reset_vardiff_stats(c);
		}
		// return either way, since with 0 shares the math below doesn't work.
		return;
	}
	
	// first, let's check if we're wayyyy out of line on what we want for diff, and respond accordingly
	
	// we need at least 1 second of data
	if (delta_tsms < 1000) return;
	
	ms_per_share = delta_tsms / m->share_count_since_snap;
	if (!ms_per_share) ms_per_share = 1;
	target_ms_share = (uint64_t)60000/(uint64_t)datum_config.stratum_v1_vardiff_target_shares_min;
	
	// we want to target X shares/minute
	// that would be 60000/X ms per share on average
	// if we're *significantly* faster than this, we'll want to bump diff immediately
	if ((!m->quickdiff_active) && (!no_quick) && (ms_per_share < (target_ms_share/(uint64_t)datum_config.stratum_v1_vardiff_quickdiff_delta))) {
		// let's say if we're at 64/shares/min or higher, we'll do a quick bump
		
		// reusing this var...
		// try to set the difficulty quickly to a value that makes some sense based on how many shares we just saw
		delta_tsms = roundDownToPowerOfTwo_64((target_ms_share / ms_per_share) * m->current_diff);
		if (delta_tsms < (m->current_diff << 2)) {
			delta_tsms = (m->current_diff << 2);
		}
		
		m->current_diff = delta_tsms;
		
		// send a special clean=true stratum job to the client
		// this will send the new diff also
		send_mining_notify(c, true, true, false);
		
		// reset the vardiff stats to start this process over again
		reset_vardiff_stats(c);
		
		// nothing else to do
		return;
	}
	
	// check if we need a diff bump downward
	if (ms_per_share > (target_ms_share*2)) {
		// adjust diff downward a tick
		m->current_diff = m->current_diff >> 1;
		if (m->current_diff < m->forced_high_min_diff) {
			m->current_diff = m->forced_high_min_diff;
		}
		if (m->current_diff < datum_config.stratum_v1_vardiff_min) {
			m->current_diff = datum_config.stratum_v1_vardiff_min;
		}
		reset_vardiff_stats(c);
		return;
	}
	
	// don't bother with looking to bump unless we have 16 shares to work with
	if (m->share_count_since_snap < 16) return;
	
	if (ms_per_share < (target_ms_share/2)) {
		// adjust diff upward a tick
		m->current_diff = m->current_diff << 1;
		reset_vardiff_stats(c);
		return;
	}
	
	// nothing to do yet
	return;
}

#define STAT_CYCLE_MS 60000

void stratum_update_miner_stats_accepted(T_DATUM_CLIENT_DATA *c, uint64_t diff_accepted) {
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	
	m->stats.diff_accepted[m->stats.active_index?1:0] += diff_accepted;
	m->stats.last_share_tsms = m->sdata->loop_tsms;
	
	if (m->sdata->loop_tsms >= (m->stats.last_swap_tsms+STAT_CYCLE_MS)) {
		m->stats.last_swap_ms = m->sdata->loop_tsms - m->stats.last_swap_tsms;
		m->stats.last_swap_tsms = m->sdata->loop_tsms;
		if (m->stats.active_index) {
			m->stats.active_index = 0;
			m->stats.diff_accepted[0] = 0;
		} else {
			m->stats.active_index = 1;
			m->stats.diff_accepted[1] = 0;
		}
	}
}

// CAUTION: modname MUST be part of username_s following a tilde
const char *datum_stratum_mod_username(const char *username_s, char * const username_buf, const size_t username_buf_sz, const uint16_t share_rnd, const char * const modname, const size_t modname_len) {
	struct datum_username_mod * const umod = datum_username_mods_find(datum_config.stratum_username_mod, modname, modname_len);
	if (!umod) return username_s;
	
	struct datum_addr_range *range;
	for (range = umod->ranges; ; ++range) {
		if (!range->addr) return datum_config.mining_pool_address;
		if (share_rnd <= range->max) break;
	}
	
	const char * const tilde = &modname[-1];
	if (range->addr_len == 0) {
		size_t len = tilde - username_s;
		if (len >= username_buf_sz) len = username_buf_sz - 1;
		memcpy(username_buf, username_s, len);
		username_buf[len] = '\0';
		return username_buf;
	}
	
	const char * const period = strchr(username_s, '.');
	if (range->addr_len >= username_buf_sz || !period) {
		return range->addr;
	}
	
	memcpy(username_buf, range->addr, range->addr_len);
	size_t len = tilde - period;
	const size_t max_len = username_buf_sz - range->addr_len - 1;
	if (len > max_len) len = max_len;
	memcpy(&username_buf[range->addr_len], period, len);
	username_buf[range->addr_len + len] = '\0';
	return username_buf;
}

int client_mining_submit(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj) {
	// {"params": ["username", "job", "extranonce2", "time", "nonce", "version"], "id": 1, "method": "mining.submit"}
	// 0 = username
	// 1 = jobid
	// 2 = extranonce2
	// 3 = ntime
	// 4 = nonce
	// 5 = version roll (OR with version)
	
	json_t *username;
	json_t *job_id;
	json_t *extranonce2;
	json_t *ntime;
	json_t *nonce;
	json_t *vroll;
	
	T_DATUM_STRATUM_JOB *job = NULL;
	
	const char *job_id_s;
	const char *vroll_s;
	const char *username_s;
	char username_buf[0x100];
	const char *extranonce2_s;
	const char *ntime_s;
	const char *nonce_s;
	
	uint32_t vroll_uint;
	
	uint16_t g_job_index;
	uint32_t bver;
	uint32_t ntime_val;
	uint32_t nonce_val;
	unsigned char coinbase_index = 0;
	T_DATUM_STRATUM_COINBASE *cb = NULL;
	unsigned char extranonce_bin[12];
	
	unsigned char block_header[80];
	unsigned char digest_temp[40];	unsigned char share_hash[40];
	unsigned char full_cb_txn[MAX_COINBASE_TXN_SIZE_BYTES];
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	if (!m->authorized) {
		send_error_to_client(c, id, "[24,\"unauthorized\",null]");
		return 0;
	}
	if (!datum_security_consume_submit(c)) {
		send_error_to_client(c, id, "[25,\"rate-limit\",null]");
		return 0;
	}
	int i;
	bool quickdiff = false;
	bool empty_work = false;
	bool was_block = false;
	char new_notify_blockhash[65];
	
	// 0 = version 4 bytes
	// 4 = previous block hash 32 bytes
	// 36 = merkle root 32 bytes
	// 68 = ntime
	// 72 = nbits
	// 76 = nonce
	
	// see if this is a real job
	job_id = json_array_get(params_obj, 1);
	if (!job_id) {
		send_unknown_work_error(c,id);
		m->share_count_rejected++;
		m->share_diff_rejected+=m->last_sent_diff; // guestimate here
		return 0;
	}
	
	job_id_s = json_string_value(job_id);
	if (!job_id_s) {
		send_unknown_work_error(c,id);
		m->share_count_rejected++;
		m->share_diff_rejected+=m->last_sent_diff; // guestimate here
		return 0;
	}
	
	if (strlen(job_id_s) != 16) {
		if ((strlen(job_id_s) == 17) && (job_id_s[0] == 'Q')) {
			// was a quick diff change job. discard the Q at the front
			job_id_s++;
			quickdiff = true;
		} else if ((strlen(job_id_s) == 17) && (job_id_s[0] == 'N')) {
			// new block empty work.  means we use coinbase 0 and we have no merkle leafs
			job_id_s++;
			empty_work = true;
		} else {
			send_unknown_work_error(c,id);
			m->share_count_rejected++;
			m->share_diff_rejected+=m->last_sent_diff; // guestimate here
			return 0;
		}
	}
	
	// jobID is
	// 4 bytes time (who cares)
	// 1 byte raw index kinda (useless)
	// 2 bytes global ptr index
	// 1 byte coinbase index used
	// 6625a3d53cc0e500
	// 0123456789ABCDEF
	g_job_index = (hex2bin_uchar(&job_id_s[0xA])<<8) | hex2bin_uchar(&job_id_s[0xC]);
	g_job_index ^= STRATUM_JOB_INDEX_XOR;
	if (g_job_index >= MAX_STRATUM_JOBS) {
		send_unknown_work_error(c,id);
		m->share_count_rejected++;
		m->share_diff_rejected+=m->last_sent_diff; // guestimate here
		return 0;
	}
	
	job = global_cur_stratum_jobs[g_job_index];
	
	if (!job) {
		send_unknown_work_error(c,id);
		m->share_count_rejected++;
		m->share_diff_rejected+=m->last_sent_diff; // guestimate here
		return 0;
	}
	
	if (upk_u64le(job->job_id, 0) != upk_u64le(job_id_s, 0)) {
		//LOG_PRINTF("DEBUG: Job ID for index %u doesn't match expected in RAM. (%s vs %s)", g_job_index, job->job_id, job_id_s);
		send_unknown_work_error(c,id);
		m->share_count_rejected++;
		m->share_diff_rejected+=m->last_sent_diff; // guestimate here
		return 0;
	}
	
	const uint64_t job_diff = quickdiff ? m->quickdiff_value : m->stratum_job_diffs[g_job_index];
	
	// construct block header
	bver = job->version_uint;
	if (m->extension_version_rolling) {
		vroll = json_array_get(params_obj, 5);
		if (!vroll) {
			// version rolling requested, but missing from this work submission
			send_bad_version_error(c,id);
			m->share_count_rejected++;
			m->share_diff_rejected += job_diff;
			return 0;
		}
		vroll_s = json_string_value(vroll);
		if (!vroll_s) {
			// couldn't get string
			send_bad_version_error(c,id);
			m->share_count_rejected++;
			m->share_diff_rejected += job_diff;
			return 0;
		}
		vroll_uint = strtoul(vroll_s, NULL, 16);
		if ((vroll_uint & m->extension_version_rolling_mask) != vroll_uint) {
			// tried to roll bits we didn't approve
			send_bad_version_error(c,id);
			m->share_count_rejected++;
			m->share_diff_rejected += job_diff;
			return 0;
		}
		bver |= vroll_uint;
	}
	
	// 0 - 4 = version
	pk_u32le(block_header, 0, bver);
	
	// 4 - 35 = previous block hash
	memcpy(&block_header[4], job->prevhash_bin, 32);
	
	// 36 - 67 = merkle root
	// need to get the extranonce together
	pk_u32le(extranonce_bin, 0, m->sid_inv);
	extranonce2 = json_array_get(params_obj, 2);
	if (!extranonce2) {
		send_unknown_work_error(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	extranonce2_s = json_string_value(extranonce2);
	if (!extranonce2_s) {
		send_unknown_work_error(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	if (strlen(extranonce2_s) != 16) {
		send_unknown_work_error(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	for(i=0;i<8;i++) {
		extranonce_bin[i+4] = hex2bin_uchar(&extranonce2_s[i<<1]);
	}
	
	// need to build the full coinbase txn
	coinbase_index = hex2bin_uchar(&job_id_s[0xE]);
	if (coinbase_index >= MAX_COINBASE_TYPES) {
		if (!(empty_work && coinbase_index == 255)) {
			send_unknown_work_error(c, id);
			m->share_count_rejected++;
			m->share_diff_rejected += job_diff;
			return 0;
		}
	}
	
	if (empty_work) {
		cb = &job->subsidy_only_coinbase;
	} else {
		cb = &job->coinbase[coinbase_index];
	}
	
	if (!cb) {
		send_unknown_work_error(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	
	memcpy(&full_cb_txn[0], cb->coinb1_bin, cb->coinb1_len);
	memcpy(&full_cb_txn[cb->coinb1_len], extranonce_bin, 12);
	memcpy(&full_cb_txn[cb->coinb1_len+12], cb->coinb2_bin, cb->coinb2_len);
	
	// if we did a quickdiff work, we need to change our extra data just a little so it's unique.
	// if we don't do this, we're forcing the miner to redo work its already done, which is wasteful
	// and the miner would potentially see these as rejected duplicate shares.
	//
	// we only need to tweak the binary version here.
	// this is saved for the block submission and all below, also, so is safe
	
	// we also need to apply our target diff byte, which could be different depending on if quickdiff or not
	// we must encode the current diff directly into the PoW.  This allows remote DATUM servers to accept
	// our variable difficulty work (subject to the DATUM server provided global minimum)
	
	if (quickdiff) {
		if (upk_u16le(full_cb_txn, cb->coinb1_len - 2) != 0x5144) {
			pk_u16le(full_cb_txn, cb->coinb1_len - 2, 0x5144);
		} else {
			pk_u16le(full_cb_txn, cb->coinb1_len - 2, 0xAEBB);
		}
		full_cb_txn[job->target_pot_index] = floorPoT(m->quickdiff_value);
	} else {
		full_cb_txn[job->target_pot_index] = floorPoT(m->stratum_job_diffs[g_job_index]);
	}
	
	if ((job->merklebranch_count) && (!empty_work)) {
		// hash the CB txn
		double_sha256(digest_temp, full_cb_txn, cb->coinb1_len+12+cb->coinb2_len);
		
		// calc root
		stratum_job_merkle_root_calc(job, digest_temp, &block_header[36]);
	} else {
		// empty block means coinbase txn hash is the merkleroot
		double_sha256(&block_header[36], full_cb_txn, cb->coinb1_len+12+cb->coinb2_len);
	}
	
	// 68 - 71 = ntime
	ntime = json_array_get(params_obj, 3);
	if (!ntime) {
		send_unknown_work_error(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	ntime_s = json_string_value(ntime);
	if (!ntime_s) {
		send_unknown_work_error(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	ntime_val = strtoul(ntime_s, NULL, 16);
	
	pk_u32le(block_header, 68, ntime_val);
	
	// 72 - 75 = bits
	memcpy(&block_header[72], &job->nbits_bin[0], sizeof(uint32_t));
	
	// 76 - 79 = nonce
	nonce = json_array_get(params_obj, 4);
	if (!nonce) {
		send_unknown_work_error(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	nonce_s = json_string_value(nonce);
	if (!nonce_s) {
		send_unknown_work_error(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	nonce_val = strtoul(nonce_s, NULL, 16);
	pk_u32le(block_header, 76, nonce_val);
	
	my_sha256(digest_temp, block_header, 80);
	my_sha256(share_hash, digest_temp, 32);
	
	if (upk_u32le(share_hash, 28) != 0) {
		// H-not-zero
		//LOG_PRINTF("HIGH HASH: %8.8lx", (unsigned long)upk_u32le(share_hash, 28));
		send_rejected_hnotzero_error(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	
	username = json_array_get(params_obj, 0);
	if (!username) {
		username_s = (const char *)"NULL";
	} else {
		username_s = json_string_value(username);
		if (!username_s) {
			username_s = (const char *)"NULL";
		}
	}
	
	if (datum_config.stratum_username_mod) {
		const char * const tilde = strchr(username_s, '~');
		if (tilde) {
			const char * const modname = &tilde[1];
			const size_t modname_len = json_string_length(username) - (modname - username_s);
			const uint16_t share_rnd = upk_u16le(share_hash, 0);
			username_s = datum_stratum_mod_username(username_s, username_buf, sizeof(username_buf), share_rnd, modname, modname_len);
		}
	}
	
	// most important thing to do right here is to check if the share is a block
	// there's some downstream failures that can impact the share being valid, but at this point it's
	// possible for this block to be valid.  even if it's stale or something we're going to try it.
	if (compare_hashes(share_hash, job->block_target) <= 0) {
		// BLOCK
		// since we check this early, it's possible a duplicate share submission could trigger this twice... but that's alright.
		// it won't hurt to re-submit a block.
		was_block = true;
		new_notify_blockhash[64] = 0;
		for(i=0;i<32;i++) {
			uchar_to_hex((char *)&new_notify_blockhash[(31-i)<<1], share_hash[i]);
		}
		DLOG_WARN("************************************************************************************************");
		DLOG_WARN("******** BLOCK FOUND - %s ********",new_notify_blockhash);
		DLOG_WARN("************************************************************************************************");
		datum_embedded_record_block_candidate((const char *)new_notify_blockhash);
		
		i = assembleBlockAndSubmit(block_header, full_cb_txn, cb->coinb1_len+12+cb->coinb2_len, job, m->sdata, new_notify_blockhash, empty_work);
		if (i) {
			// successfully submitted
			datum_blocktemplates_notifynew(new_notify_blockhash, job->height + 1);
		}
		
		if (job->is_datum_job) {
			// submit via DATUM
			datum_protocol_pow_submit(c, job, username_s, was_block, empty_work, quickdiff, block_header, job_diff, full_cb_txn, cb, extranonce_bin, coinbase_index);
		}
	}
	
	// we check this after checking if the share is a valid block because... well, we want to try and build on our own block even on the off chance it's late.
	// we'll still reject the share, though, even if it's a block. *trollface*
	if (job->is_stale_prevblock) {
		// share is from a stale job
		send_rejected_stale_block(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	
	// check if ntime is within bounds for a valid block
	// we'll do this after we try and potential blocks found with bad times, just in case
	if (ntime_val < job->block_template->mintime) {
		send_rejected_time_too_old(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	
	if (ntime_val > (job->block_template->curtime + 7200)) {
		send_rejected_time_too_new(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	
	// check if share beats miner's work target
	if (!quickdiff) {
		// check against job+connection target
		if (compare_hashes(share_hash, m->stratum_job_targets[g_job_index]) > 0) {
			// bad target diff
			send_rejected_high_hash_error(c, id);
			m->share_count_rejected++;
			m->share_diff_rejected += job_diff;
			return 0;
		}
	} else {
		// check against quickdiff target instead
		if (compare_hashes(share_hash, m->quickdiff_target) > 0) {
			// bad target diff
			send_rejected_high_hash_error(c, id);
			m->share_count_rejected++;
			m->share_diff_rejected += job_diff;
			return 0;
		}
	}
	
	// check if stale
	if (m->sdata->loop_tsms > (job->tsms + ((datum_config.stratum_v1_share_stale_seconds + datum_config.bitcoind_work_update_seconds) * 1000))) {
		// share is from a stale job
		send_rejected_stale(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	
	// check if duplicate submission
	// if this is a quickdiff share, invert ntime here as a way to prevent unlikely collisions.
	if (datum_stratum_check_for_dupe(m->sdata, nonce_val, g_job_index, quickdiff?(~ntime_val):(ntime_val), bver, &extranonce_bin[0])) {
		send_rejected_duplicate(c, id);
		m->share_count_rejected++;
		m->share_diff_rejected += job_diff;
		return 0;
	}
	
	// work accepted
	if (!was_block) {
		if (job->is_datum_job) {
			// submit via DATUM
			datum_protocol_pow_submit(c, job, username_s, was_block, empty_work, quickdiff, block_header, job_diff, full_cb_txn, cb, extranonce_bin, coinbase_index);
		}
	}
	
	char s[256];
	snprintf(s, sizeof(s), "{\"error\":null,\"id\":%"PRIu64",\"result\":true}\n", id);
	datum_socket_send_string_to_client(c, s);
	
	// update connection totals
	m->share_diff_accepted += job_diff;
	m->share_count_accepted++;
	if ((m->share_count_accepted == 1) || ((m->share_count_accepted & 1023) == 0)) {
		DLOG_INFO("Stratum share accepted: worker=%s difficulty=%"PRIu64" block=%s accepted=%"PRIu64,
			m->last_auth_username[0] ? m->last_auth_username : "unknown",
			job_diff, was_block ? "yes" : "no", m->share_count_accepted);
	}
	
	// update since-snap totals
	m->share_count_since_snap++;
	m->share_diff_since_snap += job_diff;
	
	stratum_update_miner_stats_accepted(c, job_diff);
	stratum_update_vardiff(c,false);
	
	return 0;
}

int client_mining_configure(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj) {
	// {"id":0,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000","version-rolling.min-bit-count":16}]}
	// {"id": 9966, "method": "mining.configure", "params": [["version-rolling", "subscribe-extranonce"], {"version-rolling.mask": "1fffe000", "version-rolling.min-bit-count": 16}]}
	// {"id":1,"method":"mining.configure","params":[["version-rolling","minimum-difficulty","subscribe-extranonce"],{"version-rolling.mask":"1fffe000","version-rolling.min-bit-count":16,"minimum-difficulty.value":2048}]}
	
	// prompts the following responses:
	// {"error": null, "id": 0, "result": {"version-rolling": true, "version-rolling.mask": "1fffe000", "minimum-difficulty": false}}
	// {"id": null, "method": "mining.set_version_mask", "params": ["1fffe000"]}
	
	// need to parse params...
	
	json_t *p1, *p2, *t;
	const char *s, *s2;
	char sx[1024];
	char sa[1024];
	int sxl = 0;
	sx[0] = 0;
	int i;
	
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	
	bool new_vroll = false;
	bool new_mdiff = false;
	
	if (!json_is_array(params_obj)) {
		return -1;
	}
	
	p1 = json_array_get(params_obj, 0);
	p2 = json_array_get(params_obj, 1);
	if ((!p1) || (!p2)) return -1;
	
	size_t index;
	json_t *value;
	
	json_array_foreach(p1, index, value) {
		if (json_is_string(value)) {
			s = json_string_value(value);
			switch(s[0]) {
				case 'v': {
					if (!strcmp("version-rolling", s)) {
						new_vroll = true;
						m->extension_version_rolling = true;
						m->extension_version_rolling_mask = 0x1fffe000;
						m->extension_version_rolling_bits = 16;
						t = json_object_get(p2, "version-rolling.mask");
						if (t) {
							s2 = json_string_value(t);
							if (s2) {
								m->extension_version_rolling_mask = strtoul(s2, NULL, 16) & m->extension_version_rolling_mask;
							}
						}
						
						sxl = sprintf(&sx[sxl], "{\"id\":null,\"method\":\"mining.set_version_mask\",\"params\":[\"%08x\"]}\n", m->extension_version_rolling_mask);
					}
					break;
				}
				
				case 'm': {
					if (!strcmp("minimum-difficulty", s)) {
						new_mdiff = true;
					}
					break;
				}
				
				default: break;
			}
		}
	}
	
	i = snprintf(sa, sizeof(sa), "{\"error\":null,\"id\":%"PRIu64",\"result\":{", id);
	if (new_vroll) {
		i+= snprintf(&sa[i], sizeof(sa)-i, "\"version-rolling\":true,\"version-rolling.mask\":\"%08x\"", m->extension_version_rolling_mask);
	}
	if (new_mdiff) {
		// we don't currently support miner specified minimum difficulty.
		i+= snprintf(&sa[i], sizeof(sa)-i, ",\"minimum-difficulty\":false");
	}
	i+= snprintf(&sa[i], sizeof(sa)-i, "}}\n");
	
	datum_socket_send_string_to_client(c, sa);
	
	if (sxl) {
		datum_socket_send_string_to_client(c, sx);
	}
	
	return 0;
}

int client_mining_authorize(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj) {
	char s[256];
	const char *username_s;
	const char *password_s;
	json_t *username;
	json_t *password;
	
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	
	username = json_array_get(params_obj, 0);
	password = json_array_get(params_obj, 1);
	if (!username) {
		username_s = (const char *)"NULL";
	} else {
		username_s = json_string_value(username);
		if (!username_s) {
			username_s = (const char *)"NULL";
		}
	}
	password_s = json_is_string(password) ? json_string_value(password) : NULL;
	const size_t base_len = strlen(datum_config.stratum_v1_auth_user);
	const size_t username_len = strlen(username_s);
	bool username_chars_ok = username_len < sizeof(m->last_auth_username);
	for (size_t i = 0; username_chars_ok && i < username_len; ++i) {
		if (iscntrl((unsigned char)username_s[i])) username_chars_ok = false;
	}
	const bool username_ok = !datum_config.stratum_v1_auth_required ||
		(username_chars_ok && (!strcmp(username_s, datum_config.stratum_v1_auth_user) ||
		 (!strncmp(username_s, datum_config.stratum_v1_auth_user, base_len) &&
		  username_s[base_len] == '.' && username_s[base_len + 1] != 0)));
	const bool password_ok = !datum_config.stratum_v1_auth_required ||
		datum_secure_strequals(datum_config.stratum_v1_auth_password,
			strlen(datum_config.stratum_v1_auth_password), password_s);
	if (!username_ok || !password_ok || datum_security_ip_in_cooldown(c->rem_host)) {
		datum_security_auth_failure(c->rem_host);
		snprintf(s, sizeof(s), "{\"error\":null,\"id\":%"PRIu64",\"result\":false}\n", id);
		datum_socket_send_string_to_client(c, s);
		DLOG_WARN("Stratum authorization failed from %s", c->rem_host);
		return 0;
	}
	
	strncpy(m->last_auth_username, username_s, sizeof(m->last_auth_username) - 1);
	m->last_auth_username[sizeof(m->last_auth_username)-1] = 0;
	
	snprintf(s, sizeof(s), "{\"error\":null,\"id\":%"PRIu64",\"result\":true}\n", id);
	datum_socket_send_string_to_client(c, s);
	
	m->authorized = true;
	DLOG_INFO("Stratum worker authorized: %s", m->last_auth_username);
	if (m->subscribed) {
		send_mining_set_difficulty(c);
		send_mining_notify(c, true, false, false);
	}
	
	return 0;
}

int send_mining_notify(T_DATUM_CLIENT_DATA *c, bool clean, bool quickdiff, bool new_block) {
	// send the current job to the miner
	
	T_DATUM_THREAD_DATA *t = (T_DATUM_THREAD_DATA *)c->datum_thread;
	T_DATUM_STRATUM_JOB *j = ((T_DATUM_STRATUM_THREADPOOL_DATA *)t->app_thread_data)->cur_stratum_job;
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	T_DATUM_STRATUM_COINBASE *cb;
	char cb1[STRATUM_COINBASE1_MAX_LEN+2];
	unsigned int cbselect = 0;
	bool full_coinbase = false;
	char s[512];
	unsigned char tdiff = 0xFF;
	
	if (!j) {
		return -1;
	}
	
	//job_id - ID of the job. Use this ID while submitting share generated from this job.
	//prevhash - Hash of previous block.
	//coinb1 - Initial part of coinbase transaction.
	//coinb2 - Final part of coinbase transaction.
	//merkle_branch - List of hashes, will be used for calculation of merkle root.
	//version - Bitcoin block version.
	//nbits - Encoded current network difficulty
	//ntime - Current ntime/
	//clean_jobs
	
	// {
	// 		"id": null,
	//		"method": "mining.notify",
	//		"params": [
	//			"17137173556511577", // job_id
	//			"275476ad65c63568bfea24935f56ecbb4cafe90100030dcf0000000000000000", // prevhash
	//			"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff110326d20c0c004f4345414e2e58595a0026ffffffff020000000000000000106a0e7795", // coinb1
	//			"205fa0120000000017a914413b5901fe4e591c95405fd446b5b002da575bf08700000000", // coinb2
	//			[], // merkle_branch
	//			"20000000", // version
	//			"17034219", // nbits
	//			"6625406b", // ntime
	//			true // clean_jobs
	//		]
	//	}
	
	// let's not conflict the two special types of work. empty block is more important than changing vardiff quickly
	if (new_block) {
		quickdiff = false;
	}
	
	// we always set difficulty before the first notify on the connection, so last_sent_diff should always be set here
	// compute the target for this job for the client
	if (!quickdiff) {
		// check for a vardiff change. call with "no_quick" set to true to prevent recursion or double notifies
		stratum_update_vardiff(c, true);
	}
	
	if (j->is_datum_job) {
		// check if our client meets of exceeds the minimum datum diff
		if (m->current_diff < datum_config.override_vardiff_min) {
			m->current_diff = datum_config.override_vardiff_min;
		}
	}
	
	// if we have an updated difficulty to send, send it before we send the notify
	// applies to quick and normal diff changes
	if (m->last_sent_diff != m->current_diff) {
		send_mining_set_difficulty(c);
	}
	
	// if this is a quick diff change, the job is likely identical to one we've already sent
	// in which case, we don't want to clobber the normal target table and reject shares that we shouldn't
	if (!quickdiff) {
		get_target_from_diff(m->stratum_job_targets[j->global_index], m->last_sent_diff);
		m->stratum_job_diffs[j->global_index] = m->last_sent_diff;
		m->quickdiff_active = false;
	} else {
		m->quickdiff_active = true;
		m->quickdiff_value = m->last_sent_diff;
		get_target_from_diff(m->quickdiff_target, m->quickdiff_value);
	}
	
	// We'll use the client's send buffer for sanity, since in this environment it wont result in a partial send and we can just build up the string in the output buffer
	datum_socket_send_string_to_client(c, "{\"id\":null,\"method\":\"mining.notify\",\"params\":[");
	
	if (j->job_state >= JOB_STATE_FULL_PRIORITY_WAIT_COINBASER) {
		if (((T_DATUM_STRATUM_THREADPOOL_DATA *)t->app_thread_data)->full_coinbase_ready) {
			full_coinbase = true;
		}
	}
	
	// coinbase selection is tacked on to the job ID
	// prepending a Q means it's a duplicate job, but with a new diff (needed per stratum protocol "spec")
	// prepending an N means this is an empty (subsidy-only) block with a small coinbase and has coinbase ID 255/0xff
	if (new_block) {
		cbselect = 0;
	} else {
		if (full_coinbase) {
			cbselect = m->coinbase_selection;
		} else {
			cbselect = 0;
		}
	}
	
	cb = &j->coinbase[cbselect];
	// new block work always is just a blank coinbase, for now
	
	if (quickdiff) {
		snprintf(s, sizeof(s), "\"Q%s%2.2x\",\"%s\",\"", j->job_id, cbselect, j->prevhash);
	} else {
		if (!new_block) {
			snprintf(s, sizeof(s), "\"%s%2.2x\",\"%s\",\"", j->job_id, cbselect, j->prevhash);
		} else {
			snprintf(s, sizeof(s), "\"N%s%2.2x\",\"%s\",\"", j->job_id, (unsigned int)255, j->prevhash); // empty coinbase for new block
			cb = &j->subsidy_only_coinbase;
		}
	}
	
	// this may look silly, but the send buffer doesn't get emptied until this thread's loop runs. so might as well just utilize it
	// for code readability purposes at the expense of a few extra calls.
	datum_socket_send_string_to_client(c, s);
	memcpy(cb1, cb->coinb1, cb->coinb1_len<<1); // copy coinb1 to temp buffer for user-specific modifications
	cb1[cb->coinb1_len<<1] = 0;
	
	// the miner's PoT diff needs to be encoded here.
	// TODO: Rework job ID to include the target byte.  This is gateway side, and the server doesn't care at all about the SV1 job ID.
	tdiff = floorPoT(m->last_sent_diff);
	uchar_to_hex(&cb1[j->target_pot_index<<1], tdiff);
	
	if (quickdiff) {
		// in a quickdiff, we need to replace the last two bytes of coinb1 to make the work unique
		// while the quickdiff value here is non-unique per user in the case of multiple quickdiffs for the same job, the extranonce1
		// is still unique per user and mitigates this.
		
		// NOTE: These constants are also used by the DATUM server.  DO NOT CHANGE THEM.
		datum_socket_send_chars_to_client(c, cb1, (cb->coinb1_len<<1)-4);
		
		if (upk_u16le(cb->coinb1_bin, cb->coinb1_len - 2) != 0x5144) {
			datum_socket_send_string_to_client(c, "4451");
		} else {
			datum_socket_send_string_to_client(c, "BBAE");
		}
	} else {
		datum_socket_send_string_to_client(c, cb1);
	}
	datum_socket_send_string_to_client(c, "\",\"");
	datum_socket_send_string_to_client(c, cb->coinb2);
	datum_socket_send_string_to_client(c, "\",");
	
	if (!new_block) {
		// send job merkle leafs
		datum_socket_send_string_to_client(c, j->merklebranches_full);
	} else {
		// send empty merkle leafs
		datum_socket_send_string_to_client(c, "[]");
	}
	snprintf(s, sizeof(s), ",\"%s\",\"%s\",\"%s\",", j->version, j->nbits, j->ntime);
	datum_socket_send_string_to_client(c, s);
	
	// bunch of reasons we may need to discard old work
	if ((clean) || (quickdiff) || (new_block)) {
		datum_socket_send_string_to_client(c, "true]}\n");
	} else {
		datum_socket_send_string_to_client(c, "false]}\n");
	}
	
	m->last_sent_stratum_job_index = j->global_index;
	
	return 0;
}

int send_mining_set_difficulty(T_DATUM_CLIENT_DATA *c) {
	char s[256];
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	
	if (!m->current_diff) {
		const uint64_t difficulty = datum_embedded_get_share_difficulty();
		m->current_diff = difficulty ? difficulty : datum_config.stratum_v1_vardiff_min;
	}
	
	snprintf(s, sizeof(s), "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[%"PRIu64"]}\n", (uint64_t)m->current_diff);
	datum_socket_send_string_to_client(c, s);
	
	m->last_sent_diff = m->current_diff;
	
	return 0;
}

void datum_stratum_fingerprint_by_UA(T_DATUM_MINER_DATA *m) {
	// TODO: Make this a little more efficient. perhaps move to a loadable definitions file of some kind.
	
	// S21 tested to handle 2.25KB coinbase work on all versions released
	// UA starts with: Antminer S21/
	// S21 Pro NOT confirmed to work this way (yet)... so keep the /
	if (strstr(m->useragent, "Antminer S21/") == m->useragent) {
		m->coinbase_selection = 5; // ANTMAIN2
		return;
	}
	
	// the ePIC control boards can handle almost any size coinbase
	// UA starts with: PowerPlay-BM/
	if (strstr(m->useragent, "PowerPlay-BM/") == m->useragent) {
		m->coinbase_selection = 4; // YUGE
		return;
	}
	
	// "vinsh" reports as xminer
	// Tested to handle up to 16KB
	if (strstr(m->useragent, "xminer-1.") == m->useragent) {
		m->coinbase_selection = 4; // YUGE
		return;
	}
	
	// whatsminer works fine with about a 6.5 KB coinbase
	// UA starts with: whatsminer/v1
	if (strstr(m->useragent, "whatsminer/v1") == m->useragent) {
		m->coinbase_selection = 3; // RESPECTABLE
		return;
	}
	
	// Braiins firmware
	// Appears to handle arbitrary coinbase sizes, however not extensively tested on all firmware versions
	// feed the S21-like coinbase for now, which is at least moderately sized
	// UA contains: bosminer-plus-tuner
	if (strstr(m->useragent, "bosminer-plus-tuner") != NULL) { // match anywhere in string, not just beginning
		m->coinbase_selection = 5; // ANTMAIN2
		return;
	}
	
	// Nicehash, sadly needs a smaller coinbase than even antminer s19s
	// they also need a high minimum difficulty
	if (strstr(m->useragent, "NiceHash/") == m->useragent) {
		if (!datum_config.stratum_v1_fixed_difficulty) {
			m->current_diff=524288;
			m->forced_high_min_diff=524288;
		}
		m->coinbase_selection = 1; // TINY
		return;
	}
	
	// The Bitaxe is tested to work with a large coinbase
	// However, it does slow work changes slightly when they're YUGE, so we'll go with
	// the whatsminer tested size as a compromise.  also should save some bandwidth, which
	// is probably not a bad plan, given the low odds of a bitaxe finding a block.
	if (strstr(m->useragent, "bitaxe") == m->useragent) {
		m->coinbase_selection = 3; // RESPECTABLE
		return;
	}
}

int client_mining_subscribe(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj) {
	uint32_t sid;
	char s[1024];
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	json_t *useragent;
	
	// params =
	// 0 = UA
	// 1 = session ID to resume
	// 2 = host/port
	// 3 = ???
	
	if (m->subscribed) {
		// don't resubscribe them... that'd be dumb.
		return 0;
	}
	
	// set default diff
	m->current_diff = datum_config.stratum_v1_vardiff_min;
	
	// default to the antminer workaround, which appears to be universally compatible
	// except for NiceHash.
	m->coinbase_selection = 2;
	
	m->useragent[0] = 0;
	if (params_obj) {
		if (json_is_array(params_obj)) {
			useragent = json_array_get(params_obj, 0);
			if (json_is_string(useragent)) {
				strncpy_uachars(m->useragent, json_string_value(useragent), 127); // strip some chars
				m->useragent[127] = 0;
			}
		}
	}
	
	if ((datum_config.stratum_v1_fingerprint_miners) && (m->useragent[0])) {
		datum_stratum_fingerprint_by_UA(m);
		if (m->current_diff < datum_config.stratum_v1_vardiff_min) {
			m->current_diff = datum_config.stratum_v1_vardiff_min;
		}
	}
	
	// get a new unique session ID for this connection (extranonce1)
	sid = get_new_session_id(c);
	m->sid = sid;
	
	// store the inverted endian version for faster share checking later
	m->sid_inv = ((sid>>24)&0xff) | (((sid>>16)&0xff)<<8) | (((sid>>8)&0xff)<<16) | ((sid&0xff)<<24);
	
	// tell them about all of this
	snprintf(s, sizeof(s), "{\"error\":null,\"id\":%"PRIu64",\"result\":[[[\"mining.notify\",\"%8.8x1\"],[\"mining.set_difficulty\",\"%8.8x2\"]],\"%8.8x\",8]}\n", id, sid, sid, sid);
	datum_socket_send_string_to_client(c, s);
	
	// mark them as subscribed so that notifies actually work
	m->subscribed = true;
	
	if (m->authorized) {
		// Send usable work only after authorization.
		send_mining_set_difficulty(c);
		send_mining_notify(c,true,false,false);
	}
	
	// reset vardiff tallies
	m->share_count_since_snap = 0;
	m->share_diff_since_snap = 0;
	m->share_snap_tsms = m->sdata->loop_tsms;
	m->subscribe_tsms = m->sdata->loop_tsms;
	
	return 0;
}

int datum_stratum_v1_socket_thread_client_cmd(T_DATUM_CLIENT_DATA *c, char *line) {
	json_t *j ,*method_obj, *id_obj, *params_obj;
	json_error_t err = { };
	const char *method;
	int i;
	uint64_t id;
	
	if (line[0] == 0) return 0;
	
	if (line[0] != '{') {
		return -1;
	}
	
	j = json_loads(line, JSON_REJECT_DUPLICATES, &err);
	if (!j) {
		return -2;
	}
	
	if (!(method_obj = json_object_get(j, "method"))) {
		json_decref(j);
		return -3;
	}
	
	if (!json_is_string(method_obj)) {
		json_decref(j);
		return -6;
	}
	
	// id can technically be anything, but we should enforce some sanity...
	if (!(id_obj = json_object_get(j, "id"))) {
		json_decref(j);
		return -4;
	}
	
	// enforce that id must be an integer.  might not be 100% to spec, but is sane and nothing known violates this.
	// allowing arbitrary non-integer things here is a potential DoS vector.
	if (!json_is_integer(id_obj)) {
		json_decref(j);
		return -4;
	}
	
	id = json_integer_value(id_obj);
	
	if (!(params_obj = json_object_get(j, "params"))) {
		json_decref(j);
		return -5;
	}
	
	method = json_string_value(method_obj);
	
	if (method[0] == 0) {
		json_decref(j);
		return -7;
	}
	
	switch (method[0]) {
		case 'm': {
			if (!strcmp(method, "mining.submit")) {
				i = client_mining_submit(c, id, params_obj);
				json_decref(j);
				return i;
			}
			if (!strcmp(method, "mining.configure")) {
				i = client_mining_configure(c, id, params_obj);
				json_decref(j);
				return i;
			}
			if (!strcmp(method, "mining.subscribe")) {
				i = client_mining_subscribe(c, id, params_obj);
				json_decref(j);
				return i;
			}
			if (!strcmp(method, "mining.authorize")) {
				i = client_mining_authorize(c, id, params_obj);
				json_decref(j);
				return i;
			}
			/* fallthrough */
		}
		default: {
			send_error_to_client(c, id, "[-3,\"Method not found\",null]");
			json_decref(j);
			return 0;
		}
	}
}

void stratum_job_merkle_root_calc(T_DATUM_STRATUM_JOB *s, unsigned char *coinbase_txn_hash, unsigned char *merkle_root_output) {
	int i;
	unsigned char combined[64];
	unsigned char next[32];
	
	if (!s->merklebranch_count) {
		memcpy(merkle_root_output, coinbase_txn_hash, 32);
		return;
	}
	
	memcpy(&combined[0], coinbase_txn_hash, 32);
	memcpy(&combined[32], s->merklebranches_bin[0], 32);
	double_sha256(next, combined, 64);
	
	for(i=1;i<s->merklebranch_count;i++) {
		memcpy(&combined[0], next, 32);
		memcpy(&combined[32], s->merklebranches_bin[i], 32);
		double_sha256(next, combined, 64);
	}
	
	memcpy(merkle_root_output, next, 32);
	return;
}

void stratum_calculate_merkle_branches(T_DATUM_STRATUM_JOB *s) {
	// NOTE: This uses a static varaible for temp space. Do not call concurrently from multiple threads.
	bool level_needs_dupe = false;
	int current_level_size = 0, next_level_size = 0;
	int q,i,j;
	
	// 64 byte combined hashes for inputs to merkle hashes
	unsigned char combined[64];
	
	// pointers for hash lists
	const unsigned char (*current_level)[32];
	unsigned char (*next_level)[32];
	
	// scratch RAM
	static unsigned char templist[16384][32];
	
	// dev sanity check for thread concurrency
	static int safety_check;
	int marker = ++safety_check;
	
	if (s->block_template->txn_count > 16383) {
		DLOG_FATAL("BUG: stratum_calculate_merkle_branches does not support templates with more than 16383 transactions! %d transactions in template.",(int)s->block_template->txn_count);
		panic_from_thread(__LINE__);
		return;
	}
	
	if (!s->block_template->txn_count) {
		// no transactions
		s->merklebranch_count = 0;
		s->merklebranches_full[0] = '[';
		s->merklebranches_full[1] = ']';
		s->merklebranches_full[2] = 0;
		return;
	}
	
	current_level_size = s->block_template->txn_count+1;
	
	next_level = &templist[0];
	current_level = next_level;
	level_needs_dupe = false;
	q = 0;
	while (current_level_size > 1) {
		if (current_level_size % 2 != 0) {
			current_level_size++;
			level_needs_dupe = true;
		} else {
			level_needs_dupe = false;
		}
		
		next_level_size = current_level_size >> 1;
		
		for(i=0;i<next_level_size;i++) {
			if (!i) {
				if (!q) {
					// first level branch
					memcpy(s->merklebranches_bin[0], s->block_template->txns[0].txid_bin, 32);
					for(j=0;j<32;j++) {
						pk_u16le(s->merklebranches_hex[0], j << 1, upk_u16le(s->block_template->txns[0].txid_hex, (31 - j) << 1));
					}
					s->merklebranches_hex[0][64] = 0;
				} else {
					// second+ level branch
					if (level_needs_dupe && (i==(next_level_size-1))) {
						memcpy(s->merklebranches_bin[q], &current_level[i<<1][0], 32);
					} else {
						memcpy(s->merklebranches_bin[q], &current_level[(i<<1)+1][0], 32);
					}
					hash2hex(s->merklebranches_bin[q], s->merklebranches_hex[q]);
				}
			} else {
				if (!q) {
					// getting from txn list
					// we're pretending we have a coinbase txn that we don't know about yet at index -1, so
					// we need to pretend we're one txn ahead of where we really are.
					// That means expected index-1 is our first, and index is our second. This is not a typo!
					memcpy(&combined[0], s->block_template->txns[(i<<1)-1].txid_bin, 32);
					if (level_needs_dupe && (i==(next_level_size-1))) {
						memcpy(&combined[32], s->block_template->txns[(i<<1)-1].txid_bin, 32);
					} else {
						memcpy(&combined[32], s->block_template->txns[(i<<1)].txid_bin, 32);
					}
				} else {
					// getting from "current_level"
					memcpy(&combined[0], &current_level[i<<1][0], 32);
					if (level_needs_dupe && (i==(next_level_size-1))) {
						memcpy(&combined[32], &current_level[i<<1][0], 32);
					} else {
						memcpy(&combined[32], &current_level[(i<<1)+1][0], 32);
					}
				}
				
				double_sha256(next_level[i], combined, 64);
			}
		}
		current_level = next_level;
		next_level+=i+1;
		current_level_size = next_level_size;
		q++;
	}
	
	s->merklebranch_count = q;
	
	// Pre-construct stratum v1 job field
	s->merklebranches_full[0] = '[';
	j=1;
	for(i=0;i<q;i++) {
		if (i) {
			s->merklebranches_full[j] = ',';
			j++;
		}
		j += sprintf(&s->merklebranches_full[j], "\"%s\"", s->merklebranches_hex[i]);
	}
	s->merklebranches_full[j] = ']';
	s->merklebranches_full[j+1] = 0;
	
	if (safety_check != marker) {
		DLOG_FATAL("BUG: stratum_calculate_merkle_branches is NOT thread safe and appears to have been called concurrently!");
		panic_from_thread(__LINE__);
	}
}

void update_stratum_job(T_DATUM_TEMPLATE_DATA *block_template, bool new_block, int job_state) {
	T_DATUM_STRATUM_JOB *s = &stratum_job_list[stratum_job_next];
	int i;
	
	// clear the job memory
	memset(s, 0, sizeof(T_DATUM_STRATUM_JOB));
	
	// come up with a prefix for the job
	// this ensures it is unique even if nothing else about the job has changed for some reason
	s->enprefix = stratum_enprefix ^ 0xB10C;
	stratum_enprefix++;
	
	// copy the template's previous block hash in 32-bit LE hex
	for(i=0;i<8;i++) {
		pk_u64le(s->prevhash, i << 3, upk_u64le(block_template->previousblockhash, (7 - i) << 3));
	}
	s->prevhash[64] = 0;
	
	snprintf(s->version, sizeof(s->version), "%8.8x", block_template->version);
	s->version_uint = block_template->version;
	strncpy(s->nbits, block_template->bits, sizeof(s->nbits) - 1);
	
	// TODO: Should we use local time, and just verify is valid for the block?
	// Perhaps as an option.
	// The template's time is 100% safe, so we'll use that for now.
	snprintf(s->ntime, sizeof(s->ntime), "%8.8llx", (unsigned long long)block_template->curtime);
	
	// Set the coinbase value of this job based on the template
	s->coinbase_value = block_template->coinbasevalue;
	s->height = block_template->height;
	s->block_template = block_template;
	
	// stash useful binary versions of prevblockhash and nbits
	memcpy(s->prevhash_bin, block_template->previousblockhash_bin, 32);
	memcpy(s->nbits_bin, block_template->bits_bin, 4);
	s->nbits_uint = upk_u32le(s->nbits_bin, 0);
	
	// calculate block target from nbits
	nbits_to_target(s->nbits_uint, s->block_target);
	
	// if this is to be a clean job, remember that
	s->is_new_block = new_block;
	
	// we're new, not stale
	s->is_stale_prevblock = false;
	
	// start as not a datum job.  if we have coinbase data and such for it down the line, this will get updated.
	s->is_datum_job = false;
	
	// prep the coinbase txn(s) for this job
	generate_base_coinbase_txns_for_stratum_job(s, s->is_new_block);
	
	s->job_state = job_state;
	if ((job_state == JOB_STATE_FULL_PRIORITY_WAIT_COINBASER) || (job_state == JOB_STATE_FULL_NORMAL_WAIT_COINBASER)) {
		s->need_coinbaser = true;
	} else {
		s->need_coinbaser = false;
	}
	
	// if this is a new block, invalidate all old work
	if (new_block) {
		for(i=0;i<MAX_STRATUM_JOBS;i++) {
			if (i != stratum_job_next) {
				stratum_job_list[i].is_stale_prevblock = true;
			}
		}
	}
	
	// increment the next job index (global)
	stratum_job_next++;
	if (stratum_job_next == MAX_STRATUM_JOBS) stratum_job_next = 0;
	
	// timestamp the job
	s->tsms = current_time_millis();
	
	// calculate the stratum merkle branches and store them on this job
	stratum_calculate_merkle_branches(s);
	
	// update the latest empty data before we update the global job
	// this way, this info is here when all of the threads switch jobs
	if (new_block) {
		pthread_rwlock_wrlock(&stratum_global_latest_empty_stat);
		stratum_latest_empty_complete_count = 0; // reset # of threads completed
		stratum_latest_empty_ready_for_full = false; // reset ready-for-full.
		stratum_latest_empty_sent_count = 0; // reset client count
		stratum_latest_empty_job_index = global_latest_stratum_job_index+1;
		if (stratum_latest_empty_job_index == MAX_STRATUM_JOBS) {
			stratum_latest_empty_job_index = 0;
		}
		pthread_rwlock_unlock(&stratum_global_latest_empty_stat);
	}
	
	if (s->is_datum_job) {
		s->datum_job_idx = datum_protocol_setup_new_job_idx(s);
	}
	
	// update and sync the current global job index
	pthread_rwlock_wrlock(&stratum_global_job_ptr_lock);
	
	global_latest_stratum_job_index++;
	if (global_latest_stratum_job_index == MAX_STRATUM_JOBS) {
		global_latest_stratum_job_index = 0;
	}
	
	s->global_index = global_latest_stratum_job_index;
	snprintf(s->job_id, sizeof(s->job_id), "%8.8x%2.2x%4.4x", (uint32_t)time(NULL), (uint8_t)stratum_job_next, (unsigned int)((uint16_t)s->global_index ^ STRATUM_JOB_INDEX_XOR));
	
	global_cur_stratum_jobs[global_latest_stratum_job_index] = s;
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
	
	DLOG_DEBUG("Updated to job %d, ncb = %d, state = %d", s->global_index, s->need_coinbaser?1:0, s->job_state);
	
	return;
}

int assembleBlockAndSubmit(uint8_t *block_header, uint8_t *coinbase_txn, size_t coinbase_txn_size, T_DATUM_STRATUM_JOB *job, T_DATUM_STRATUM_THREADPOOL_DATA *sdata, const char *block_hash_hex, bool empty_work) {
	// TODO: Also submit directly to bitcoin P2P
	char *submitblock_req = NULL;
	char *ptr = NULL;
	size_t i;
	json_t *r;
	CURL *tcurl;
	int ret = 0;
	bool free_submitblock_req = false;
	char *s = NULL;
	
	// each thread has a chunk of RAM dedicated to prepping block submissions. use it.
	submitblock_req = sdata->submitblock_req;
	
	if (!submitblock_req) {
		// This should NEVER happen and likely indicates something is terribly wrong with the state of things... but we'll try our best to salvage this block.
		DLOG_ERROR("For some reason no pointer available for submitting the block we just found! Attempting to allocate new memory for this, but we're probably in for a bad time...");
		submitblock_req = malloc(8500000); // worst case
		if (!submitblock_req) {
			// this would be really bad
			DLOG_FATAL("Could not allocate RAM for submitblock! This is REALLY bad.");
			// TODO: dump what we can to disk to preserve the block for any watchdog available there
			// This should never happen, however, so super low priority... but to cover every contingency when a block is involved is eventually important to do.
			panic_from_thread(__LINE__);
			return 0;
		}
		DLOG_ERROR("We were able to allocate a new block of RAM for submitting this block. But look into this issue. May be a hardware or OS problem!");
		free_submitblock_req = true;
	}
	
	ptr = submitblock_req;
	ptr += sprintf(ptr, "{\"jsonrpc\":\"1.0\",\"id\":\"%llu\",\"method\":\"submitblock\",\"params\":[\"",(unsigned long long)time(NULL));
	for(i=0;i<80;i++) {
		ptr += sprintf(ptr, "%2.2x", block_header[i]);
	}
	
	// txn count
	if (!empty_work) {
		ptr += append_bitcoin_varint_hex(job->block_template->txn_count + 1, ptr);
	} else {
		ptr += append_bitcoin_varint_hex(1, ptr);
	}
	
	// copy coinbase txn
	for(i=0;i<coinbase_txn_size;i++) {
		ptr += sprintf(ptr, "%2.2x", coinbase_txn[i]);
	}
	
	if (!empty_work) {
		// copy all of the block transaction data to the buffer
		for(i=0;i<job->block_template->txn_count;i++) {
			memcpy(ptr, job->block_template->txns[i].txn_data_hex, job->block_template->txns[i].size*2);
			ptr += job->block_template->txns[i].size*2;
		}
	}
	
	// close the submitblock
	*ptr = '"'; ptr++;
	*ptr = ']'; ptr++;
	*ptr = '}'; ptr++;
	*ptr = 0;
	
	// logging function will truncate the output
	DLOG_DEBUG("Block Payload: %s", submitblock_req);
	
	// Trigger our redundant submission thread
	datum_submitblock_trigger(submitblock_req, block_hash_hex);
	
	// while this may induce a tiny delay for writing to disk, that seems favorable to losing the block entirely
	// if something below were to fail/crash/etc
	// this way we can have a (future) external watchdog monitoring the folder as a backup to submit the blocks if need be
	// for added security.  The thread above should already be submitting this block anyway.
	if (datum_config.mining_save_submitblocks_dir[0] != 0) {
		// save the block submission to a file named by the block's hash
		char submitblockpath[384];
		int n = snprintf(submitblockpath, sizeof(submitblockpath), "%s/datum_submitblock_%s.json", datum_config.mining_save_submitblocks_dir, block_hash_hex);
		
		if (n >= sizeof(submitblockpath)) {
			DLOG_ERROR("Overflow in construction of submitblock path!");
		} else {
			FILE *f;
			f = fopen(submitblockpath, "w");
			if (!f) {
				DLOG_ERROR("Could not open %s for writing submitblock record to disk: %s!", submitblockpath, strerror(errno));
			} else {
				if (!fwrite(submitblock_req, ptr-submitblock_req, 1, f)) {
					DLOG_ERROR("Could not write to %s when writing submitblock record to disk: %s!", submitblockpath, strerror(errno));
				}
				fclose(f);
			}
		}
	}
	
	tcurl = curl_easy_init();
	if (!tcurl) {
		DLOG_FATAL("Could not initialize cURL for submitblock!!! This is REALLY REALLY BAD.");
		// we're not going to panic here because our other thread might still pull off submitting it...
		// these are cosmic ray rarity situations that should just never happen.
		usleep(100000);
		return 0;
	}
	
	// make the call!
	r = bitcoind_json_rpc_call(tcurl, &datum_config, submitblock_req);
	curl_easy_cleanup(tcurl);
	if (!r) {
		// oddly, this means success here.
		DLOG_INFO("Block %s submitted to upstream node successfully!",block_hash_hex);
		datum_embedded_record_block_result(block_hash_hex, true, "accepted");
		ret = 1;
	} else {
		s = json_dumps(r, JSON_ENCODE_ANY);
		if (!s) {
			DLOG_WARN("Upstream node rejected our block! (unknown)");
			datum_embedded_record_block_result(block_hash_hex, false, "rejected: unknown");
		} else {
			DLOG_WARN("Upstream node rejected our block! (%s)",s);
			datum_embedded_record_block_result(block_hash_hex, false, "rejected by upstream node");
			free(s);
		}
		json_decref(r);
		ret = 0;
	}
	
	// cleanup
	if (free_submitblock_req) {
		// let's not free until our thread is done with it
		usleep(10000);
		datum_submitblock_waitfree();
		free(submitblock_req);
	}
	
	return ret;
}
