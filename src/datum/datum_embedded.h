/* Copyright (c) 2026 The Bitcoin Purity developers
 * Distributed under the MIT software license. */
#ifndef BITCOIN_DATUM_EMBEDDED_H
#define BITCOIN_DATUM_EMBEDDED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* listen_address;
    uint16_t listen_port;
    uint32_t max_clients;
    uint32_t max_clients_per_ip;
    bool auth_required;
    const char* auth_user;
    const char* auth_password;
    uint32_t auth_timeout_seconds;
    const char* rpc_url;
    const char* rpc_user;
    const char* rpc_password;
    const char* rpc_cookie_file;
    const unsigned char* payout_script;
    size_t payout_script_len;
    const char* payout_address;
    uint64_t share_difficulty;
    const char* coinbase_tag;
} datum_embedded_config;

#define DATUM_STATUS_TEXT_SIZE 256
#define DATUM_STATUS_NAME_SIZE 192
#define DATUM_STATUS_HOST_SIZE 65
#define DATUM_STATUS_USER_AGENT_SIZE 128

typedef struct {
    char worker[DATUM_STATUS_NAME_SIZE];
    char remote_host[DATUM_STATUS_HOST_SIZE];
    char user_agent[DATUM_STATUS_USER_AGENT_SIZE];
    bool subscribed;
    bool authorized;
    uint64_t connected_since_ms;
    uint64_t current_difficulty;
    double estimated_hashrate_ths;
    uint64_t accepted_shares;
    uint64_t rejected_shares;
    uint64_t last_share_time_ms;
} datum_embedded_miner_stats;

typedef struct {
    bool running;
    bool stopping;
    uint32_t clients;
    uint32_t subscribed_clients;
    uint32_t authorized_clients;
    uint64_t accepted_shares;
    uint64_t rejected_shares;
    uint64_t session_accepted_shares;
    uint64_t session_rejected_shares;
    uint64_t session_started_ms;
    uint64_t last_share_time_ms;
    double estimated_hashrate_ths;
    uint64_t current_height;
    char job_id[32];
    uint64_t job_created_ms;
    char previous_block_hash[72];
    uint32_t nbits;
    uint32_t transaction_count;
    uint32_t template_size;
    uint32_t template_weight;
    uint64_t coinbase_value;
    uint64_t last_template_update_ms;
    bool last_template_success;
    char last_template_error[DATUM_STATUS_TEXT_SIZE];
    uint64_t block_candidates;
    uint64_t block_submissions_accepted;
    uint64_t block_submissions_rejected;
    uint64_t last_block_time_ms;
    char last_block_hash[72];
    char last_block_result[DATUM_STATUS_TEXT_SIZE];
    uint64_t last_rejected_share_time_ms;
    char last_rejected_share_reason[64];
    uint64_t rejected_unknown_work;
    uint64_t rejected_high_hash;
    uint64_t rejected_stale;
    uint64_t rejected_duplicate;
    uint64_t rejected_other;
} datum_embedded_stats;

int datum_embedded_start(const datum_embedded_config* config, char* error, size_t error_size);
void datum_embedded_interrupt(void);
void datum_embedded_stop(void);
void datum_request_template_refresh(void);
bool datum_embedded_should_stop(void);
void datum_embedded_request_stop(void);
void datum_embedded_get_stats(datum_embedded_stats* stats);
uint32_t datum_embedded_get_miner_stats(datum_embedded_miner_stats* miners, uint32_t capacity);
uint64_t datum_embedded_get_share_difficulty(void);
int datum_embedded_update_share_difficulty(uint64_t difficulty, char* error, size_t error_size);
int datum_embedded_update_payout_and_coinbase(const unsigned char* payout_script, size_t payout_script_len,
                                              const char* coinbase_tag, char* error, size_t error_size);
int datum_embedded_copy_payout_script(unsigned char* payout_script, size_t payout_script_capacity, size_t* payout_script_len);
int datum_embedded_copy_coinbase_tag(char* coinbase_tag, size_t coinbase_tag_capacity);
void datum_embedded_record_template_result(bool success, const char* error);
void datum_embedded_record_block_candidate(const char* block_hash);
void datum_embedded_record_block_result(const char* block_hash, bool accepted, const char* result);

/* Implemented by the C++ bridge. */
void datum_bridge_log(int level, const char* message);
void datum_bridge_fatal_error(const char* message);

#ifdef __cplusplus
}
#endif

#endif
