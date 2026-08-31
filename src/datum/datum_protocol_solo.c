/* Solo-only compatibility seam for upstream DATUM mining code. */
#include "datum_protocol.h"

uint64_t datum_accepted_share_count;
uint64_t datum_accepted_share_diff;
uint64_t datum_rejected_share_count;
uint64_t datum_rejected_share_diff;

int datum_protocol_init(void) { return 0; }
bool datum_protocol_is_active(void) { return false; }
int datum_protocol_coinbaser_fetch(void* s) { (void)s; return 0; }
int datum_protocol_pow_submit(const T_DATUM_CLIENT_DATA* c, const T_DATUM_STRATUM_JOB* job,
    const char* username, bool was_block, bool subsidy_only, bool quickdiff,
    const unsigned char* block_header, uint64_t target_diff,
    const unsigned char* full_cb_tx, const T_DATUM_STRATUM_COINBASE* cb,
    unsigned char* extranonce, unsigned char coinbase_index)
{
    (void)c; (void)job; (void)username; (void)was_block; (void)subsidy_only;
    (void)quickdiff; (void)block_header; (void)target_diff; (void)full_cb_tx;
    (void)cb; (void)extranonce; (void)coinbase_index;
    return 0;
}
bool datum_protocol_thread_is_active(void) { return false; }
void datum_protocol_start_connector(void) {}
unsigned char datum_protocol_setup_new_job_idx(void* sx) { (void)sx; return 0; }

