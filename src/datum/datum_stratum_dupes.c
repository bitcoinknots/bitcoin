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

#include <stddef.h>
#include <string.h>
#include "datum_thread.h"
#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>

#include "datum_stratum_dupes.h"
#include "datum_stratum.h"
#include "datum_conf.h"
#include "datum_utils.h"

// TODO: Refactor to just use the block header sanely.
// This is more contrived than it needs to be, although it profiles quite well

void datum_stratum_dupes_init(void *sdata_v) {
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = sdata_v;
	T_DATUM_STRATUM_DUPES *dupes = NULL;
	sdata->dupes = calloc(  sizeof(T_DATUM_STRATUM_DUPES) + 16, 1 );
	if (!sdata->dupes) {
		DLOG_FATAL("Could not allocate RAM for dupe struct (small one, %lu bytes)", (unsigned long)sizeof(T_DATUM_STRATUM_DUPES) + 16);
		panic_from_thread(__LINE__);
		return;
	}
	
	dupes = sdata->dupes;
	
	dupes->ptr = calloc((datum_config.stratum_v1_max_clients_per_thread * datum_config.stratum_v1_vardiff_target_shares_min * (datum_config.stratum_v1_share_stale_seconds/60) * 16), sizeof(T_DATUM_STRATUM_DUPE_ITEM) );
	if (!dupes->ptr) {
		DLOG_FATAL("Could not allocate RAM for dupe struct (big one, %zu bytes)", (size_t)(datum_config.stratum_v1_max_clients_per_thread * datum_config.stratum_v1_vardiff_target_shares_min * (datum_config.stratum_v1_share_stale_seconds / 60) * 16) * sizeof(T_DATUM_STRATUM_DUPE_ITEM));
		panic_from_thread(__LINE__);
		return;
	}
	
	dupes->max_items = (datum_config.stratum_v1_max_clients_per_thread * datum_config.stratum_v1_vardiff_target_shares_min * (datum_config.stratum_v1_share_stale_seconds/60) * 16);
	dupes->current_items = 0;
	
	DLOG_DEBUG("Initialized dupe check thread data. %"PRIu64" bytes of RAM used for %d max entries @ %p for %p", (uint64_t)dupes->max_items * (uint64_t)sizeof(T_DATUM_STRATUM_DUPE_ITEM), dupes->max_items, dupes, sdata);
	
	return;
}

int datum_stratum_dupes_cleanup_sort_compare(const void *a, const void *b) {
	const T_DATUM_STRATUM_DUPE_ITEM *item1 = a;
	const T_DATUM_STRATUM_DUPE_ITEM *item2 = b;
	
	if (item1 == NULL && item2 == NULL) return 0;
	if (item1 == NULL) return 1;
	if (item2 == NULL) return -1;
	
	if (item1->job_index >= MAX_STRATUM_JOBS) return 1;
	if (item2->job_index >= MAX_STRATUM_JOBS) return -1;
	
	if (global_cur_stratum_jobs[item1->job_index] == NULL && global_cur_stratum_jobs[item2->job_index] == NULL) return 0;
	if (global_cur_stratum_jobs[item1->job_index] == NULL) return 1;
	if (global_cur_stratum_jobs[item2->job_index] == NULL) return -1;
	
	uint64_t tsms1 = global_cur_stratum_jobs[item1->job_index]->tsms;
	uint64_t tsms2 = global_cur_stratum_jobs[item2->job_index]->tsms;
	
	if (tsms1 > tsms2) return -1;
	if (tsms1 < tsms2) return 1;
	return 0;
}

int find_first_less_than(T_DATUM_STRATUM_DUPE_ITEM *ptr, size_t max_items, uint64_t given_tsms) {
	int low = 0;
	int high = max_items - 1;
	int result = -1;
	uint64_t tsms;
	
	while (low <= high) {
		int mid = low + (high - low) / 2;
		
		// sanity
		if (mid < 0) mid = 0;
		if (mid > (max_items-1)) mid = max_items-1;
		
		// more sanity
		if (ptr[mid].job_index < 0 || ptr[mid].job_index >= MAX_STRATUM_JOBS) {
			tsms = 0;
		} else if (global_cur_stratum_jobs[ptr[mid].job_index] != NULL) {
			tsms = global_cur_stratum_jobs[ptr[mid].job_index]->tsms;
		} else {
			tsms = 0;  // Treat NULL as the smallest possible value... we can trim NULLs
		}
		
		// bsearch until we find the first entry < given
		if (tsms < given_tsms) {
			result = mid;
			high = mid - 1;
		} else {
			low = mid + 1;
		}
	}
	
	return result;
}

void datum_stratum_dupes_expand(T_DATUM_STRATUM_DUPES *dupes) {
	T_DATUM_STRATUM_DUPE_ITEM *new_ptr;
	int new_max = ((dupes->max_items * 125)/100);
	new_ptr = realloc(dupes->ptr, sizeof(T_DATUM_STRATUM_DUPE_ITEM) * new_max);
	if (!new_ptr) {
		DLOG_FATAL("Could not reallocate dupes ptr %p of %d items to %d items!", dupes->ptr, dupes->max_items, new_max);
		panic_from_thread(__LINE__);
		return;
	}
	memset(&new_ptr[dupes->max_items], 0, sizeof(T_DATUM_STRATUM_DUPE_ITEM) * (new_max - dupes->max_items));
	DLOG_DEBUG("INFO: Had to allocate more RAM to duplicate share checking for thread.  %d to %d items (%"PRIu64" bytes)", dupes->max_items, new_max, (uint64_t)sizeof(T_DATUM_STRATUM_DUPE_ITEM) * (uint64_t)new_max);
	
	dupes->max_items = new_max;
	dupes->ptr = new_ptr;
	
	// always needs reoganizing after this... do externally.
}

void datum_stratum_dupes_reorganize(T_DATUM_STRATUM_DUPES *dupes) {
	int i;
	T_DATUM_STRATUM_DUPE_ITEM *q,*p=NULL;
	
	for(i=0;i<dupes->max_items;i++) {
		// we'll use ntime as an indicator, since obvious ntime cant be zero
		if (dupes->ptr[i].ntime == 0) break;
		
		if (!dupes->index[dupes->ptr[i].nonce_high]) {
			// easy. this is the first
			dupes->index[dupes->ptr[i].nonce_high] = &dupes->ptr[i];
			dupes->ptr[i].next = NULL;
			continue;
		}
		
		q = dupes->index[dupes->ptr[i].nonce_high];
		p = NULL;
		do {
			if (q->nonce_low > dupes->ptr[i].nonce_low) {
				if (p) {
					// insert after p
					p->next = &dupes->ptr[i];
				} else {
					// insert as first entry, before this one
					dupes->index[dupes->ptr[i].nonce_high] = &dupes->ptr[i];
				}
				dupes->ptr[i].next = q;
				break;
			}
			
			// this should be safe here, even though we haven't cleaned up all the old pointers
			// the reason is that nothing we having cleaned should have ended up in the index yet
			p = q;
			if (!q->next) {
				// ended up at the last entry without finding one greater than me... add to the end
				q->next = &dupes->ptr[i];
				dupes->ptr[i].next = NULL;
				q = NULL;
				break;
			} else {
				q = q->next;
			}
		} while(q);
	}
	
	dupes->current_items = i;
	
	// should be all straightened out now
}

void datum_stratum_dupes_cleanup(T_DATUM_STRATUM_DUPES *dupes, bool full_wipe) {
	int i;
	
	if (full_wipe) {
		// we're just cleaning up after a new block or whatever
		memset(dupes->ptr, 0, sizeof(T_DATUM_STRATUM_DUPE_ITEM) * dupes->max_items);
		dupes->current_items = 0;
		return;
	}
	
	// Somewhat expensive cleanup of dupes...
	// first, sort the full dupe list by the dupe's stratum job timestamp, decending... which is trickyish
	// then, bsearch find the index of the first item with a job timestamp that is from a stale job
	// if there are entries after it, we're good and we can prune those
	// fix the linked list
	
	// this breaks all links. we'll need to reconstruct them!
	qsort(dupes->ptr, dupes->max_items, sizeof(T_DATUM_STRATUM_DUPE_ITEM), datum_stratum_dupes_cleanup_sort_compare);
	
	// links all broken, so wipe out the starting table
	memset(dupes->index, 0, sizeof(T_DATUM_STRATUM_DUPE_ITEM *) * 65536);
	
	// find the first stale index
	i = find_first_less_than(dupes->ptr, dupes->max_items, current_time_millis() - (datum_config.stratum_v1_share_stale_seconds*1000));
	
	if ((i == -1) || (i == dupes->max_items-1)) {
		// none of the items are stale...
		datum_stratum_dupes_expand(dupes);
	} else {
		// ok, we want to free up at least 5% of the entries, otherwise we'll be right back here wasting CPU time
		if (i < ((dupes->max_items * 95)/100)) {
			// at least 5% are good
			// clear out the stales...
			dupes->current_items = i;
			memset(&dupes->ptr[i], 0, sizeof(T_DATUM_STRATUM_DUPE_ITEM) * (dupes->max_items - i));
		} else {
			// < 5% are freeable... we just need more RAM.
			datum_stratum_dupes_expand(dupes);
		}
	}
	
	// fix all the links in our now either expanded or cleaned dupe list
	datum_stratum_dupes_reorganize(dupes);
}

T_DATUM_STRATUM_DUPE_ITEM *datum_stratum_add_new_dupe(T_DATUM_STRATUM_DUPES *dupes, unsigned int nonce, unsigned short job_index, unsigned int ntime_val, unsigned int version_bits, unsigned char *extranonce_bin, T_DATUM_STRATUM_DUPE_ITEM *insert_after) {
	T_DATUM_STRATUM_DUPE_ITEM *i;
	
	i = &dupes->ptr[dupes->current_items];
	if (!i) {
		DLOG_FATAL("Could not add entry to dupe table!");
		panic_from_thread(__LINE__);
		return NULL;
	}
	i->nonce_high = nonce&0xFFFF;
	i->nonce_low = (nonce>>16) & 0xFFFF;
	i->job_index = job_index;
	i->ntime = ntime_val;
	i->version_bits = version_bits;
	i->extra_nonce_a = *((uint64_t *)&extranonce_bin[0]);
	i->extra_nonce_b = *((uint32_t *)&extranonce_bin[8]);
	if (!insert_after) {
		// is a new entry
		i->next = NULL;
	} else {
		i->next = insert_after->next;
		insert_after->next = i;
	}
	dupes->current_items++;
	
	if (dupes->current_items >= dupes->max_items) {
		datum_stratum_dupes_cleanup(dupes, false);
	}
	
	return i;
}

bool datum_stratum_check_for_dupe(T_DATUM_STRATUM_THREADPOOL_DATA *t, unsigned int nonce, unsigned short job_index, unsigned int ntime_val, unsigned int version_bits, unsigned char *extranonce_bin) {
	// check if a share is a dupe
	// if so, say so
	// if not, add to the
	T_DATUM_STRATUM_DUPES *dupes;
	unsigned short nonce_high = nonce&0xFFFF;
	unsigned short nonce_low;
	
	T_DATUM_STRATUM_DUPE_ITEM *i, *p = NULL;
	
	if (!t) {
		DLOG_FATAL("Threadpool data not available?!");
		panic_from_thread(__LINE__);
		return true;
	}
	
	dupes = t->dupes;
	
	if (dupes->index[nonce_high] == NULL) {
		// first nonce of its kind!
		// not a duplicate
		// add the new first entry!
		dupes->index[nonce_high] = datum_stratum_add_new_dupe(dupes, nonce, job_index, ntime_val, version_bits, extranonce_bin, NULL);
		return false;
	}
	
	// ok, there's an entry.  go through the list
	i = dupes->index[nonce_high];
	nonce_low = (nonce>>16) & 0xFFFF;
	
	do {
		if (i->nonce_low > nonce_low) {
			// we've reached a nonce higher than ours, so we can't be a dupe
			// we need to keep the list in order, so we need to insert ourselves before this entry (so, the previous entry)
			if (p) {
				datum_stratum_add_new_dupe(dupes, nonce, job_index, ntime_val, version_bits, extranonce_bin, p);
			} else {
				// we need to replace the first item in a list, so... let's make a new entry
				p = datum_stratum_add_new_dupe(dupes, nonce, job_index, ntime_val, version_bits, extranonce_bin, NULL);
				dupes->index[nonce_high] = p;
				p->next = i;
			}
			//LOG_PRINTF("DEBUG: Not dupe, nonce_low higher --- %d > %d", i->nonce_low, nonce_low);
			return false;
		}
		
		// there can be more than one nonce that's equal, so can't just assume until we pass it or
		if (i->nonce_low == nonce_low) {
			// same nonce as us, so need to do the slow checks
			if (job_index == i->job_index) {
				// same job index...
				if (ntime_val == i->ntime) {
					// same ntime....!
					if (version_bits == i->version_bits) {
						// same version bits?!?!?!?
						if (i->extra_nonce_a == *((uint64_t *)&extranonce_bin[0])) {
							// same extra nonce 1?!?!?!??!
							if (i->extra_nonce_b == *((uint32_t *)&extranonce_bin[8])) {
								// ok, this is a duplicate :(
								return true;
							}
						}
					}
				}
			}
		}
		
		// store the current ptr for the next loop
		p = i;
		
		// setup i to be the next link
		// if it's the end of the chain, this will be NULL and the loop will break
		i = i->next;
	} while (i);
	
	// we reached the end of the list, and haven't found a dupe
	// means that all of the nonces in the list are lower than us, or the last nonce is equal but doesn't match us
	// so we should be safe to insert ourselves on to the end of the list and return
	datum_stratum_add_new_dupe(dupes, nonce, job_index, ntime_val, version_bits, extranonce_bin, p);
	return false;
}

#if 0

void datum_stratum_dupes_codetest(void) {
	int i;
	uint64_t t;
	bool r;
	unsigned char en[12] = { 0 };
	int stratum_job_next = 0;
	T_DATUM_STRATUM_JOB *stratum_job_list;
	unsigned int nonce;
	
	// make a fake thread pool
	T_DATUM_STRATUM_THREADPOOL_DATA tp;
	
	datum_stratum_dupes_init(&tp);
	T_DATUM_STRATUM_DUPES *dupes = tp.dupes;
	
	stratum_job_list = calloc(MAX_STRATUM_JOBS,sizeof(T_DATUM_STRATUM_JOB));
	
	t = current_time_millis() - (datum_config.stratum_v1_share_stale_seconds*2000);
	
	// fill stratum jobs with garbage tsms
	for(i=0;i<MAX_STRATUM_JOBS;i++) {
		global_cur_stratum_jobs[i] = &stratum_job_list[stratum_job_next];
		stratum_job_next++;
		if (stratum_job_next == MAX_STRATUM_JOBS) stratum_job_next = 0;
		global_cur_stratum_jobs[i]->tsms = t;
		t+=1000000000;
	}
	
	for(i=0;i<(datum_config.stratum_v1_max_clients_per_thread * datum_config.stratum_v1_vardiff_target_shares_min * (datum_config.stratum_v1_share_stale_seconds/60) * 16)*80;i++) {
		en[0]=i%256;
		en[7]=en[0]^0xAA;
		nonce = ((i&0xFFFF)<<16)|(((i>>2)&0xFFFF)^0xFFFF);
		r = datum_stratum_check_for_dupe(&tp, nonce, (i^0x69) % MAX_STRATUM_JOBS, t/1000, 0x20000000 | i, &en[0]);
		r = datum_stratum_check_for_dupe(&tp, nonce, (i^0x69) % MAX_STRATUM_JOBS, t/1000, 0x20000000 | i, &en[0]);
		if (!r) {
			DLOG_DEBUG("MISSED A DUPE 1 - %d - %8.8x - %d / %4.4x",i, nonce , nonce & 0xFFFF, nonce & 0xFFFF);
		}
		r = datum_stratum_check_for_dupe(&tp, nonce, (i^0x69) % MAX_STRATUM_JOBS, t/1000, 0x20000000 | i, &en[0]);
		if (!r) {
			DLOG_DEBUG("MISSED A DUPE 2 - %d - %8.8x - %d / %4.4x",i, nonce , nonce & 0xFFFF, nonce & 0xFFFF);
		}
	}
	
	r = datum_stratum_check_for_dupe(&tp, 0xdeadc0de, 12, t, 0x20000001, &en[0]);
	DLOG_DEBUG("B %d %d %d",r?1:0, dupes->current_items, dupes->max_items);
	
	uint64_t starttsms, endtsms;
	starttsms = current_time_millis();
	for(i=0;i<(datum_config.stratum_v1_max_clients_per_thread * datum_config.stratum_v1_vardiff_target_shares_min * (datum_config.stratum_v1_share_stale_seconds/60) * 16)*8;i++) {
		en[0]=i%256;
		en[7]=en[0]^0xAA;
		nonce = ((i&0xFFFF)<<16)|(((i>>2)&0xFFFF)^0xFFFF);
		r = datum_stratum_check_for_dupe(&tp, nonce, (i^0x69) % MAX_STRATUM_JOBS, t/1000, 0x20000000 | i, &en[0]);
		if (!r) {
			DLOG_DEBUG("MISSED A DUPE 3 - %d - %8.8x - %d / %4.4x",i, nonce , nonce & 0xFFFF, nonce & 0xFFFF);
		}
	}
	endtsms = current_time_millis();
	DLOG_DEBUG("%d dupe checks took %"PRIu64" miliseconds", (datum_config.stratum_v1_max_clients_per_thread * datum_config.stratum_v1_vardiff_target_shares_min * (datum_config.stratum_v1_share_stale_seconds/60) * 16)*80, endtsms-starttsms);
	
	free(stratum_job_list);
}

#endif
