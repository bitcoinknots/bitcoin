/* Copyright (c) 2026 The Bitcoin Purity developers
 * Distributed under the MIT software license. */
#include "datum_embedded.h"

#include "datum_blocktemplates.h"
#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_stratum.h"
#include "datum_coinbaser.h"
#include "datum_submitblock.h"
#include "datum_time.h"
#include "datum_utils.h"

#include <curl/curl.h>
#include <errno.h>
#include <limits.h>
#include "datum_thread.h"
#include "datum_net.h"
#include <sodium.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

global_config_t datum_config;
const char* datum_gateway_config_filename = NULL;
const char* const* datum_argv = NULL;

static atomic_bool g_stop = true;
static atomic_bool g_running = false;
static atomic_uint_fast64_t g_share_difficulty;
static pthread_t g_template_thread;
static pthread_t g_stratum_thread;
static bool g_template_started;
static bool g_stratum_started;
static bool g_coinbaser_started;
static bool g_curl_initialized;
static bool g_net_initialized;
static pthread_mutex_t g_status_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_coinbase_config_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned char g_runtime_payout_script[sizeof(datum_config.mining_pool_script)];
static size_t g_runtime_payout_script_len;
static char g_runtime_coinbase_tag[sizeof(datum_config.mining_coinbase_tag_primary)];
static uint64_t g_session_started_ms;
static uint64_t g_last_template_update_ms;
static bool g_last_template_success;
static char g_last_template_error[DATUM_STATUS_TEXT_SIZE];
static uint64_t g_block_candidates;
static uint64_t g_block_submissions_accepted;
static uint64_t g_block_submissions_rejected;
static uint64_t g_last_block_time_ms;
static char g_last_block_hash[72];
static char g_last_block_result[DATUM_STATUS_TEXT_SIZE];

static bool copy_string(char* dst, size_t dst_size, const char* src,
    const char* name, char* error, size_t error_size)
{
    if (!src) src = "";
    if (strlen(src) >= dst_size) {
        snprintf(error, error_size, "%s is too long", name);
        return false;
    }
    memcpy(dst, src, strlen(src) + 1);
    return true;
}

static void set_runtime_coinbase_config(const unsigned char* payout_script, size_t payout_script_len, const char* coinbase_tag)
{
    pthread_mutex_lock(&g_coinbase_config_lock);
    memcpy(g_runtime_payout_script, payout_script, payout_script_len);
    g_runtime_payout_script_len = payout_script_len;
    snprintf(g_runtime_coinbase_tag, sizeof(g_runtime_coinbase_tag), "%s", coinbase_tag ? coinbase_tag : "");
    pthread_mutex_unlock(&g_coinbase_config_lock);
}

bool datum_embedded_should_stop(void)
{
    return atomic_load_explicit(&g_stop, memory_order_relaxed);
}

void datum_embedded_request_stop(void)
{
    atomic_store_explicit(&g_stop, true, memory_order_relaxed);
}

int datum_embedded_start(const datum_embedded_config* config, char* error, size_t error_size)
{
    if (!config || !error || error_size == 0) return -1;
    error[0] = '\0';
    if (atomic_load_explicit(&g_running, memory_order_acquire)) return 0;
    if (config->listen_port == 0 || config->max_clients == 0 ||
        config->max_clients > 4096 || config->max_clients_per_ip == 0 ||
        config->max_clients_per_ip > config->max_clients ||
        config->share_difficulty == 0 || config->share_difficulty > INT_MAX ||
        config->payout_script_len == 0 || config->payout_script_len > sizeof(datum_config.mining_pool_script)) {
        snprintf(error, error_size, "invalid embedded DATUM numeric or payout configuration");
        return -1;
    }
    if (config->auth_required &&
        ((!config->auth_user || !config->auth_user[0]) ||
         (!config->auth_password || !config->auth_password[0]))) {
        snprintf(error, error_size, "DATUM authentication requires a username and password");
        return -1;
    }

    memset(&datum_config, 0, sizeof(datum_config));
    if (!copy_string(datum_config.stratum_v1_listen_addr, sizeof(datum_config.stratum_v1_listen_addr), config->listen_address, "datumlisten", error, error_size) ||
        !copy_string(datum_config.stratum_v1_auth_user, sizeof(datum_config.stratum_v1_auth_user), config->auth_user, "datumuser", error, error_size) ||
        !copy_string(datum_config.stratum_v1_auth_password, sizeof(datum_config.stratum_v1_auth_password), config->auth_password, "datumpassword", error, error_size) ||
        !copy_string(datum_config.bitcoind_rpcurl, sizeof(datum_config.bitcoind_rpcurl), config->rpc_url, "datumrpcurl", error, error_size) ||
        !copy_string(datum_config.bitcoind_rpcuser, sizeof(datum_config.bitcoind_rpcuser), config->rpc_user, "datumrpcuser", error, error_size) ||
        !copy_string(datum_config.bitcoind_rpcpassword, sizeof(datum_config.bitcoind_rpcpassword), config->rpc_password, "datumrpcpassword", error, error_size) ||
        !copy_string(datum_config.bitcoind_rpccookiefile, sizeof(datum_config.bitcoind_rpccookiefile), config->rpc_cookie_file, "rpccookiefile", error, error_size) ||
        !copy_string(datum_config.mining_pool_address, sizeof(datum_config.mining_pool_address), config->payout_address, "datumaddress", error, error_size) ||
        !copy_string(datum_config.mining_coinbase_tag_primary, sizeof(datum_config.mining_coinbase_tag_primary), config->coinbase_tag, "datumcoinbasetag", error, error_size)) {
        return -1;
    }

    datum_config.stratum_v1_listen_port = config->listen_port;
    datum_config.stratum_v1_max_clients = (int)config->max_clients;
    datum_config.stratum_v1_max_clients_per_ip = (int)config->max_clients_per_ip;
    datum_config.stratum_v1_max_threads = config->max_clients < 4 ? (int)config->max_clients : 4;
    datum_config.stratum_v1_max_clients_per_thread =
        ((int)config->max_clients + datum_config.stratum_v1_max_threads - 1) /
        datum_config.stratum_v1_max_threads;
    datum_config.stratum_v1_trust_proxy = -1;
    datum_config.stratum_v1_auth_required = config->auth_required;
    datum_config.stratum_v1_auth_timeout_seconds = (int)config->auth_timeout_seconds;
    datum_config.stratum_v1_fixed_difficulty = true;
    datum_config.stratum_v1_vardiff_min = (int)config->share_difficulty;
    datum_config.stratum_v1_vardiff_target_shares_min = 8;
    datum_config.stratum_v1_vardiff_quickdiff_count = 4;
    datum_config.stratum_v1_vardiff_quickdiff_delta = 4;
    datum_config.stratum_v1_share_stale_seconds = 150;
    datum_config.stratum_v1_idle_timeout_no_subscribe = 15;
    datum_config.stratum_v1_idle_timeout_no_share = 900;
    datum_config.stratum_v1_idle_timeout_max_last_work = 7200;
    datum_config.stratum_v1_fingerprint_miners = true;
    datum_config.bitcoind_work_update_seconds = 30;
    datum_config.bitcoind_notify_fallback = true;
    datum_config.datum_pooled_mining_only = false;
    memcpy(datum_config.mining_pool_script, config->payout_script, config->payout_script_len);
    datum_config.mining_pool_script_len = (int)config->payout_script_len;
    set_runtime_coinbase_config(config->payout_script, config->payout_script_len, config->coinbase_tag);
    update_rpc_auth(&datum_config);
    if (datum_net_init() != 0) {
        snprintf(error, error_size, "failed to initialize DATUM network support");
        return -1;
    }
    g_net_initialized = true;
    if (sodium_init() < 0 || curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        snprintf(error, error_size, "failed to initialize DATUM cryptographic or RPC support");
        datum_embedded_stop();
        return -1;
    }
    g_curl_initialized = true;
    datum_utils_init();
    datum_stratum_v1_reset_session_stats();
    pthread_mutex_lock(&g_status_lock);
    g_session_started_ms = current_time_millis();
    g_last_template_update_ms = 0;
    g_last_template_success = false;
    g_last_template_error[0] = '\0';
    g_block_candidates = 0;
    g_block_submissions_accepted = 0;
    g_block_submissions_rejected = 0;
    g_last_block_time_ms = 0;
    g_last_block_hash[0] = '\0';
    g_last_block_result[0] = '\0';
    pthread_mutex_unlock(&g_status_lock);
    atomic_store_explicit(&g_stop, false, memory_order_release);
    atomic_store_explicit(&g_share_difficulty, config->share_difficulty, memory_order_release);

    if (datum_coinbaser_init() != 0) {
        snprintf(error, error_size, "failed to start DATUM coinbase worker");
        datum_embedded_request_stop();
        datum_embedded_stop();
        return -1;
    }
    g_coinbaser_started = true;
    if (pthread_create(&g_template_thread, NULL, datum_gateway_template_thread, NULL) != 0) {
        snprintf(error, error_size, "failed to start DATUM template worker");
        datum_embedded_stop();
        return -1;
    }
    g_template_started = true;
    if (pthread_create(&g_stratum_thread, NULL, datum_stratum_v1_socket_server, NULL) != 0) {
        snprintf(error, error_size, "failed to start DATUM Stratum worker");
        datum_embedded_stop();
        return -1;
    }
    g_stratum_started = true;
    atomic_store_explicit(&g_running, true, memory_order_release);
    return 0;
}

void datum_embedded_interrupt(void)
{
    datum_embedded_request_stop();
    datum_stratum_v1_shutdown_all();
    datum_submitblock_interrupt();
}

void datum_embedded_stop(void)
{
    atomic_store_explicit(&g_running, false, memory_order_release);
    datum_embedded_interrupt();
    if (g_stratum_started) {
        pthread_join(g_stratum_thread, NULL);
        g_stratum_started = false;
    }
    if (g_template_started) {
        pthread_join(g_template_thread, NULL);
        g_template_started = false;
    }
    if (g_coinbaser_started) {
        datum_coinbaser_stop();
        g_coinbaser_started = false;
    }
    datum_submitblock_stop();
    if (g_curl_initialized) {
        curl_global_cleanup();
        g_curl_initialized = false;
    }
    if (g_net_initialized) {
        datum_net_cleanup();
        g_net_initialized = false;
    }
    sodium_memzero(&datum_config, sizeof(datum_config));
    pthread_mutex_lock(&g_coinbase_config_lock);
    memset(g_runtime_payout_script, 0, sizeof(g_runtime_payout_script));
    g_runtime_payout_script_len = 0;
    memset(g_runtime_coinbase_tag, 0, sizeof(g_runtime_coinbase_tag));
    pthread_mutex_unlock(&g_coinbase_config_lock);
    atomic_store_explicit(&g_share_difficulty, 0, memory_order_release);
}

void datum_request_template_refresh(void)
{
    if (!datum_embedded_should_stop()) datum_blocktemplates_notifynew(NULL, 0);
}

void datum_embedded_get_stats(datum_embedded_stats* stats)
{
    if (!stats) return;
    memset(stats, 0, sizeof(*stats));
    stats->running = atomic_load_explicit(&g_running, memory_order_acquire);
    stats->stopping = stats->running && datum_embedded_should_stop();
    datum_stratum_v1_get_extended_stats(stats);
    pthread_mutex_lock(&g_status_lock);
    stats->session_started_ms = g_session_started_ms;
    stats->last_template_update_ms = g_last_template_update_ms;
    stats->last_template_success = g_last_template_success;
    strncpy(stats->last_template_error, g_last_template_error, sizeof(stats->last_template_error) - 1);
    stats->block_candidates = g_block_candidates;
    stats->block_submissions_accepted = g_block_submissions_accepted;
    stats->block_submissions_rejected = g_block_submissions_rejected;
    stats->last_block_time_ms = g_last_block_time_ms;
    strncpy(stats->last_block_hash, g_last_block_hash, sizeof(stats->last_block_hash) - 1);
    strncpy(stats->last_block_result, g_last_block_result, sizeof(stats->last_block_result) - 1);
    pthread_mutex_unlock(&g_status_lock);
}

uint32_t datum_embedded_get_miner_stats(datum_embedded_miner_stats* miners, uint32_t capacity)
{
    return datum_stratum_v1_get_miner_stats(miners, capacity);
}

void datum_embedded_record_template_result(bool success, const char* error)
{
    pthread_mutex_lock(&g_status_lock);
    g_last_template_update_ms = current_time_millis();
    g_last_template_success = success;
    snprintf(g_last_template_error, sizeof(g_last_template_error), "%s", error ? error : "");
    pthread_mutex_unlock(&g_status_lock);
}

void datum_embedded_record_block_candidate(const char* block_hash)
{
    pthread_mutex_lock(&g_status_lock);
    ++g_block_candidates;
    g_last_block_time_ms = current_time_millis();
    snprintf(g_last_block_hash, sizeof(g_last_block_hash), "%s", block_hash ? block_hash : "");
    snprintf(g_last_block_result, sizeof(g_last_block_result), "pending");
    pthread_mutex_unlock(&g_status_lock);
}

void datum_embedded_record_block_result(const char* block_hash, bool accepted, const char* result)
{
    pthread_mutex_lock(&g_status_lock);
    if (accepted) ++g_block_submissions_accepted;
    else ++g_block_submissions_rejected;
    g_last_block_time_ms = current_time_millis();
    snprintf(g_last_block_hash, sizeof(g_last_block_hash), "%s", block_hash ? block_hash : "");
    snprintf(g_last_block_result, sizeof(g_last_block_result), "%s", result ? result : (accepted ? "accepted" : "rejected"));
    pthread_mutex_unlock(&g_status_lock);
}

uint64_t datum_embedded_get_share_difficulty(void)
{
    return atomic_load_explicit(&g_share_difficulty, memory_order_acquire);
}

int datum_embedded_update_share_difficulty(uint64_t difficulty, char* error, size_t error_size)
{
    if (!error || error_size == 0) return -1;
    error[0] = '\0';
    if (difficulty == 0 || difficulty > INT_MAX) {
        snprintf(error, error_size, "share difficulty must be between 1 and %d", INT_MAX);
        return -1;
    }
    if (!atomic_load_explicit(&g_running, memory_order_acquire) || datum_embedded_should_stop()) {
        snprintf(error, error_size, "DATUM is not running");
        return -1;
    }
    atomic_store_explicit(&g_share_difficulty, difficulty, memory_order_release);
    return 0;
}

int datum_embedded_update_payout_and_coinbase(const unsigned char* payout_script, size_t payout_script_len,
                                              const char* coinbase_tag, char* error, size_t error_size)
{
    if (!error || error_size == 0) return -1;
    error[0] = '\0';
    if (!payout_script || payout_script_len == 0 || payout_script_len > sizeof(g_runtime_payout_script)) {
        snprintf(error, error_size, "invalid payout script");
        return -1;
    }
    if (!coinbase_tag || strlen(coinbase_tag) >= sizeof(g_runtime_coinbase_tag)) {
        snprintf(error, error_size, "coinbase tag must be at most %zu bytes", sizeof(g_runtime_coinbase_tag) - 1);
        return -1;
    }
    if (!atomic_load_explicit(&g_running, memory_order_acquire) || datum_embedded_should_stop()) {
        snprintf(error, error_size, "DATUM is not running");
        return -1;
    }
    set_runtime_coinbase_config(payout_script, payout_script_len, coinbase_tag);
    datum_request_template_refresh();
    return 0;
}

int datum_embedded_copy_payout_script(unsigned char* payout_script, size_t payout_script_capacity, size_t* payout_script_len)
{
    if (!payout_script || !payout_script_len) return -1;
    pthread_mutex_lock(&g_coinbase_config_lock);
    if (g_runtime_payout_script_len == 0 || g_runtime_payout_script_len > payout_script_capacity) {
        pthread_mutex_unlock(&g_coinbase_config_lock);
        return -1;
    }
    memcpy(payout_script, g_runtime_payout_script, g_runtime_payout_script_len);
    *payout_script_len = g_runtime_payout_script_len;
    pthread_mutex_unlock(&g_coinbase_config_lock);
    return 0;
}

int datum_embedded_copy_coinbase_tag(char* coinbase_tag, size_t coinbase_tag_capacity)
{
    if (!coinbase_tag || coinbase_tag_capacity == 0) return -1;
    pthread_mutex_lock(&g_coinbase_config_lock);
    const size_t tag_len = strlen(g_runtime_coinbase_tag);
    if (tag_len >= coinbase_tag_capacity) {
        pthread_mutex_unlock(&g_coinbase_config_lock);
        return -1;
    }
    memcpy(coinbase_tag, g_runtime_coinbase_tag, tag_len + 1);
    pthread_mutex_unlock(&g_coinbase_config_lock);
    return 0;
}

void datum_print_banner(void) {}

const T_DATUM_CONFIG_ITEM* datum_config_get_option_info(const char* category, size_t category_len, const char* name, size_t name_len)
{ (void)category; (void)category_len; (void)name; (void)name_len; return NULL; }
const T_DATUM_CONFIG_ITEM* datum_config_get_option_info2(const char* category, const char* name)
{ (void)category; (void)name; return NULL; }
int datum_config_parse_username_mods(struct datum_username_mod** mods, json_t* item, bool log_errors)
{ (void)mods; (void)item; (void)log_errors; return 0; }
struct datum_username_mod* datum_username_mods_next(struct datum_username_mod* prev)
{ (void)prev; return NULL; }
struct datum_username_mod* datum_username_mods_find(struct datum_username_mod* mods, const char* name, size_t name_len)
{ (void)mods; (void)name; (void)name_len; return NULL; }
