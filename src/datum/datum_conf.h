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

#ifndef _DATUM_CONF_H_
#define _DATUM_CONF_H_

#define DATUM_CONFIG_MAX_ARRAY_ENTRIES 32
#define DATUM_MAX_BLOCK_SUBMITS DATUM_CONFIG_MAX_ARRAY_ENTRIES
#define DATUM_MAX_SUBMIT_URL_LEN 512

#include <stdbool.h>
#include <stdint.h>

#include <jansson.h>

enum datum_conf_vartype {
	// NOTE: Keep in sync with datum_conf_var_type_text
	DATUM_CONF_BOOL,
	DATUM_CONF_INT,
	DATUM_CONF_STRING,
	DATUM_CONF_STRING_ARRAY,
	DATUM_CONF_USERNAME_MODS,
};

typedef struct {
	char category[32];
	char name[64];
	char description[512];
	const char *example;
	bool example_default;
	enum datum_conf_vartype var_type;
	union {
		int default_int;
		bool default_bool;
		struct {
			int max_string_len;
			const char *default_string[1];
		};
	};
	
	void *ptr;
	
	bool required;
} T_DATUM_CONFIG_ITEM;

const T_DATUM_CONFIG_ITEM *datum_config_get_option_info(const char *category, size_t category_len, const char *name, size_t name_len);
const T_DATUM_CONFIG_ITEM *datum_config_get_option_info2(const char *category, const char *name);

struct datum_addr_range {
	char *addr;
	size_t addr_len;
	uint16_t max;
};

struct datum_username_mod {
	size_t sz;
	char *modname;
	size_t modname_len;
	struct datum_addr_range ranges[];
};

int datum_config_parse_username_mods(struct datum_username_mod **umods_p, json_t *item, bool log_errors);
struct datum_username_mod *datum_username_mods_next(struct datum_username_mod *prev_umod);
struct datum_username_mod *datum_username_mods_find(struct datum_username_mod *umod, const char *modname, size_t modname_len);

// Globally accessable config options
typedef struct {
	char bitcoind_rpcuserpass[256];
	char bitcoind_rpccookiefile[1024];
	char bitcoind_rpcuser[128];
	char bitcoind_rpcpassword[128];
	char bitcoind_rpcurl[256];
	int bitcoind_work_update_seconds;
	bool bitcoind_notify_fallback;
	
	char stratum_v1_listen_addr[128];
	int stratum_v1_listen_port;
	int stratum_v1_max_clients;
	int stratum_v1_max_threads;
	int stratum_v1_max_clients_per_thread;
	int stratum_v1_trust_proxy;
	
	int stratum_v1_vardiff_min;
	int stratum_v1_vardiff_target_shares_min;
	int stratum_v1_vardiff_quickdiff_count;
	int stratum_v1_vardiff_quickdiff_delta;
	int stratum_v1_share_stale_seconds;
	bool stratum_v1_fingerprint_miners;
	int stratum_v1_idle_timeout_no_subscribe;
	int stratum_v1_idle_timeout_no_share;
	int stratum_v1_idle_timeout_max_last_work;
	bool stratum_v1_auth_required;
	char stratum_v1_auth_user[192];
	char stratum_v1_auth_password[192];
	int stratum_v1_auth_timeout_seconds;
	int stratum_v1_max_clients_per_ip;
	bool stratum_v1_fixed_difficulty;
	
	void *stratum_username_mod;
	
	char mining_pool_address[256];
	unsigned char mining_pool_script[64];
	int mining_pool_script_len;
	char mining_coinbase_tag_primary[64];
	char mining_coinbase_tag_secondary[64];
	char mining_save_submitblocks_dir[256];
	int coinbase_unique_id;
	
	char api_admin_password[72];
	size_t api_admin_password_len;
	char api_csrf_token[65];
	char api_listen_addr[128];
	int api_listen_port;
	bool api_allow_insecure_auth;
	bool api_modify_conf;
	json_t *config_json;
	
	int extra_block_submissions_count;
	char extra_block_submissions_urls[DATUM_MAX_BLOCK_SUBMITS][DATUM_MAX_SUBMIT_URL_LEN];
	
	bool clog_to_file;
	bool clog_to_console;
	int clog_level_console;
	int clog_level_file;
	bool clog_calling_function;
	bool clog_to_stderr;
	bool clog_rotate_daily;
	char clog_file[1024];
	
	char datum_pool_host[1024];
	int datum_pool_port;
	bool datum_pool_pass_workers;
	bool datum_pool_pass_full_users;
	bool datum_always_pay_self;
	bool datum_pooled_mining_only;
	char datum_pool_pubkey[1024];
	int datum_protocol_global_timeout;
	uint64_t datum_protocol_global_timeout_ms;
	
	uint32_t prime_id;
	unsigned char override_mining_pool_scriptsig[256];
	int override_mining_pool_scriptsig_len;
	char override_mining_coinbase_tag_primary[256];
	uint64_t override_vardiff_min;
} global_config_t;

extern global_config_t datum_config;

int datum_read_config(const char *conffile);
void datum_gateway_help(const char *argv0);
void datum_gateway_example_conf(void);

#endif
