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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdatomic.h>
#include <jansson.h>
#include <inttypes.h>
#include <curl/curl.h>

#include "datum_conf.h"
#include "datum_gateway.h"
#include "datum_protocol.h"
#include "datum_utils.h"
#include "datum_sockets.h"
#include "datum_embedded.h"
#include "datum_net.h"
#include "datum_thread.h"
#include "datum_time.h"

int datum_active_threads = 0;
int datum_active_clients = 0;

int get_remote_ip(datum_socket_t fd, char *ip, size_t max_len) {
	struct sockaddr_storage addr;
	datum_socklen_t addr_len = sizeof(addr);
	
	// Get the address of the peer
	if (getpeername(fd, (struct sockaddr*)&addr, &addr_len) == -1) {
		strncpy(ip, "0.0.0.0", max_len);
		return -1;
	}
	
	// Check if the address is IPv4 or IPv6
	if (addr.ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		if (inet_ntop(AF_INET, &s->sin_addr, ip, max_len) == NULL) {
			strncpy(ip, "0.0.0.0", max_len);
			return -1;
		}
	} else if (addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		if (inet_ntop(AF_INET6, &s->sin6_addr, ip, max_len) == NULL) {
			strncpy(ip, "0.0.0.0", max_len);
			return -1;
		}
	} else {
		strncpy(ip, "0.0.0.0", max_len);
		return -1;
	}
	
	return 0;
}

void *datum_threadpool_thread(void *arg) {
	T_DATUM_THREAD_DATA *my = (T_DATUM_THREAD_DATA *)arg;
	int i, nfds, n, cidx, j;
	size_t leftover = 0;
	
	if (!my->app->client_cmd_func) {
		DLOG_FATAL("Thread pool thread started with no client command function pointer. :(");
		panic_from_thread(__LINE__);
		return 0;
	}
	
	// Call application specific thread init
	if (my->app->init_func) my->app->init_func(my);
	
	while(!datum_embedded_should_stop()) {
		pthread_mutex_lock(&my->thread_data_lock);
		
		if (!my->connected_clients) {
			// no clients to serve
			// shutdown this thread after some kind of timeout?
			pthread_mutex_unlock(&my->thread_data_lock);
			
			// the loop doesn't care if we have no clients...
			if (my->app->loop_func) my->app->loop_func(my);
			
			my->has_client_kill_request = false;
			my->empty_request = false;
			
			datum_sleep_micros(10000);
			continue;
		}
		
		// check if any new clients, handle them if so
		if (my->has_new_clients) {
			for(i=0;i<my->app->max_clients_thread;i++) {
				if (my->client_data[i].new_connection) {
					my->client_data[i].new_connection = false;
					my->client_data[i].in_buf = 0;
					my->client_data[i].out_buf = 0;
					my->client_data[i].proxy_line_read = 0;
					
					// call new client handler, if any
					if (my->app->new_client_func) my->app->new_client_func(&my->client_data[i]);
				}
			}
			my->has_new_clients = false;
		}
		pthread_mutex_unlock(&my->thread_data_lock);
		
		if (__builtin_expect(my->empty_request,0)) {
			// We got a request to empty all clients from our thread!
			DLOG_WARN("Executing command to empty thread (%d clients)",my->connected_clients);
			for (j = 0; j < my->app->max_clients_thread; j++) {
				if (my->client_data[j].fd != 0) {
					datum_socket_close(my->client_data[j].fd);
					
					// call closed client function, if any
					if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[j], "empty thread command");
					datum_socket_thread_client_count_decrement(my, j, true);
				}
			}
		} else if (__builtin_expect(my->has_client_kill_request,0)) {
			// the API has requested we kill a specific client
			for (j = 0; j < my->app->max_clients_thread; j++) {
				if ((my->client_data[j].fd != 0) && (my->client_data[j].kill_request)) {
					my->client_data[j].kill_request = false;
					datum_socket_close(my->client_data[j].fd);
					
					// call closed client function, if any
					if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[j], "client kill command");
					datum_socket_thread_client_count_decrement(my, j, true);
				}
			}
		}
		my->has_client_kill_request = false;
		my->empty_request = false;
		// Call application specific thread preloop
		if (my->app->loop_func) my->app->loop_func(my);
		
		// TODO: make this smarter
		// See if there's anything to write for any of our clients before looping through all potential clients.
		// Will need profiling, as this is pretty cheap to do with reasonable max_clients_thread.
		// If there's data, attempt to send it.
		for (j = 0; j < my->app->max_clients_thread; j++) {
			if ((my->client_data[j].fd != 0) && (my->client_data[j].out_buf > 0)) {
				int sent = send(my->client_data[j].fd, my->client_data[j].w_buffer, my->client_data[j].out_buf, DATUM_MSG_DONTWAIT);
				if (sent > 0) {
					if (sent < my->client_data[j].out_buf) {
						// not a full send. shift remaining data to beginning of w_buffer
						memmove(my->client_data[j].w_buffer, my->client_data[j].w_buffer + sent, my->client_data[j].out_buf - sent);
					}
					if (sent <= my->client_data[j].out_buf) {
						my->client_data[j].out_buf -= sent;
					} else {
						// should never happen
						my->client_data[j].out_buf = 0;
					}
				} else {
					if (!datum_socket_would_block()) {
						datum_socket_close(my->client_data[j].fd);
						
						// call closed client function, if any
						if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[j], "send error");
						
						datum_socket_thread_client_count_decrement(my, j, true);
					}
				}
			}
		}
		
		// Build a bounded poll set from the configured per-thread client slots.
		nfds = 0;
		for (i = 0; i < my->app->max_clients_thread; ++i) {
			if (!my->client_data[i].fd) continue;
			my->pollfds[nfds].fd = my->client_data[i].fd;
			my->pollfds[nfds].events = DATUM_POLLIN;
			my->pollfds[nfds].revents = 0;
			my->poll_client_ids[nfds++] = i;
		}
		const int ready = datum_poll(my->pollfds, (unsigned long)nfds, 7);
		if (ready < 0) {
			if (errno != EINTR) {
				DLOG_ERROR("socket poll failed");
				datum_sleep_seconds(1);
				continue;
			}
		}
		if (ready > 0) {
			for(i=0;i<nfds;i++) {
				if (!(my->pollfds[i].revents & DATUM_POLL_READY)) continue;
				cidx = my->poll_client_ids[i];
				
				if (cidx >= 0) {
				const size_t input_remaining = DATUM_STRATUM_MAX_MESSAGE_SIZE - my->client_data[cidx].in_buf;
				if (!input_remaining) {
					n = -1;
					errno = EMSGSIZE;
				} else {
					n = recv(my->client_data[cidx].fd, &my->client_data[cidx].buffer[my->client_data[cidx].in_buf], (int)input_remaining, DATUM_MSG_DONTWAIT);
				}
					if (n <= 0) {
						if ((n < 0) && datum_socket_would_block()) {
							// we epoll'd without edge triggering.  this shouldn't happen!
							DLOG_DEBUG("recv returned would block or again! shouldn't happen?");
							continue; // continue for loop
						} else {
							// an error occurred or the client closed the connection
							DLOG_DEBUG("Thread %03d event loop --- Closing fd %" PRIuPTR " (n=%d) errno=%d (%s) (req bytes: %d)", my->thread_id, (uintptr_t)my->client_data[cidx].fd, n, errno, strerror(errno), CLIENT_BUFFER - 1 - my->client_data[cidx].in_buf);
							datum_socket_close(my->client_data[cidx].fd);
							
							// call closed client function, if any
							if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[cidx], "client closed connection");
							
							datum_socket_thread_client_count_decrement(my, cidx, true);
						}
					} else {
						// null terminate the buffer for simplicity
						// this set of functions is currently only used for stratum v1-like protocols, but can easily be adopted to others.
						my->client_data[cidx].buffer[my->client_data[cidx].in_buf+n] = 0;
						
						char *start_line = my->client_data[cidx].buffer;
						char *end_line = strchr(start_line, '\n');
						
						while (end_line != NULL) {
							*end_line = 0; // null terminate the line
							if (datum_config.stratum_v1_trust_proxy != -1 && my->client_data[cidx].proxy_line_read != -1) {
								if (strncmp(start_line, "PROXY ", 6) == 0) {
									my->client_data[cidx].proxy_line_read += 1;
									if (my->client_data[cidx].proxy_line_read <= datum_config.stratum_v1_trust_proxy) {
										char src_ip[DATUM_MAX_IP_LEN + 1];
										int matched = sscanf(start_line, "PROXY TCP4 %15s", src_ip);
										if (matched != 1) {
											matched = sscanf(start_line, "PROXY TCP6 %45s", src_ip);
										}
										if (matched == 1 && src_ip[0] != 0) {
											DLOG_DEBUG("New proxy IP detected: %s on TID: %d, CID: %d", src_ip, my->thread_id, my->client_data[cidx].cid);
											strcpy(my->client_data[cidx].rem_host, src_ip);
										}
										else {
											DLOG_DEBUG("PROXY line present but no valid IP found, keeping original source IP: %s on TID: %d, CID: %d", my->client_data[cidx].rem_host, my->thread_id, my->client_data[cidx].cid);
										}
									}
									start_line = end_line + 1;
									end_line = strchr(start_line, '\n');
									continue;
								} else {
									DLOG_DEBUG("Received non-PROXY line from client %d/%d", my->thread_id, my->client_data[cidx].cid);
									my->client_data[cidx].proxy_line_read = -1;
								}
							}
							// this function can not be NULL
							j = my->app->client_cmd_func(&my->client_data[cidx], start_line);
							if (j < 0) {
								//LOG_PRINTF("Thread %03d --- Closing fd %d (client_cmd_func returned %d)", my->thread_id, my->client_data[cidx].fd, j);
								datum_socket_close(my->client_data[cidx].fd);
								
								// call closed client function, if any
								if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[cidx], "client_cmd_func returned error");
								
								datum_socket_thread_client_count_decrement(my, cidx, true);
								start_line[0] = 0;
								break;
							}
							start_line = end_line + 1;
							end_line = strchr(start_line, '\n');
						}
						
						// If any data is leftover, shift it to the beginning of the buffer
						// TODO: Implement a buffer type that doesn't require memmove on a partial read
						if (start_line[0] != 0) {
							leftover = strlen(start_line); // we null terminate the buffer above
							if (leftover) {
								memmove(my->client_data[cidx].buffer, start_line, leftover+1); // we null terminated the read above, remember?
							}
						} else {
							leftover = 0;
						}
						my->client_data[cidx].in_buf = leftover;
					if (my->client_data[cidx].in_buf >= DATUM_STRATUM_MAX_MESSAGE_SIZE) {
							// buffer overrun. lose the data. will probably break things, so punt the client. this shouldn't happen with sane clients.
							my->client_data[cidx].in_buf = 0;
							my->client_data[cidx].buffer[0] = 0;
							
							datum_socket_close(my->client_data[cidx].fd);
							
							// call closed client function, if any
							if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[cidx], "read buffer overrun before client command break");
							
							datum_socket_thread_client_count_decrement(my, cidx, true);
						}
					}
				}
				
			}
		}
	}
	
	for (i = 0; i < my->app->max_clients_thread; ++i) {
		if (my->client_data[i].fd != 0) {
			datum_socket_close(my->client_data[i].fd);
			if (my->app->closed_client_func) my->app->closed_client_func(&my->client_data[i], "DATUM shutdown");
			my->client_data[i].fd = 0;
		}
	}
	my->is_active = false;
	return NULL;
}

void clean_thread_data(T_DATUM_THREAD_DATA *d, T_DATUM_SOCKET_APP *app) {
	int i,ret;
	
	// clean up clients, just in case
	for(i=0;i<app->max_clients_thread;i++) {
		d->client_data[i].new_connection = false;
		d->client_data[i].fd = 0;
		d->client_data[i].in_buf = 0;
		d->client_data[i].out_buf = 0;
	}
	
	d->connected_clients = 0;
	d->next_open_client_index = 0;
	
	d->has_new_clients = false;
	
	memset(d->pollfds, 0, sizeof(datum_pollfd) * app->max_clients_thread);
	
	// init the mutex
	ret = pthread_mutex_init(&d->thread_data_lock, NULL);
	if (ret) {
		DLOG_FATAL("Could not init mutex for thread data: %s", strerror(ret));
		panic_from_thread(__LINE__);
		return;
	}
	
	// fix the app pointer
	d->app = app;
}

int assign_to_thread(T_DATUM_SOCKET_APP *app, datum_socket_t fd) {
	// Only one thread will be calling this function for a particular "app"
	// under the current design.  Safe to assume that multiple clients will
	// not cause overlap here.
	
	// Check how many threads are active.
	// If < max, put the client on a new thread.
	// If all threads are active, then it should find the one with the fewest clients and place the new client there.
	
	int i,j,ret,tc=0;
	char remote_ip[DATUM_MAX_IP_LEN + 1];
	if (get_remote_ip(fd, remote_ip, DATUM_MAX_IP_LEN) != 0) return 0;
	int per_ip = 0;
	for (i = 0; i < app->max_threads; ++i) {
		for (j = 0; j < app->max_clients_thread; ++j) {
			if (app->datum_threads[i].client_data[j].fd > 0 &&
				!strcmp(app->datum_threads[i].client_data[j].rem_host, remote_ip)) ++per_ip;
		}
	}
	if (per_ip >= datum_config.stratum_v1_max_clients_per_ip) {
		DLOG_WARN("Rejecting Stratum connection from %s at per-IP limit", remote_ip);
		return 0;
	}
	
	int tid=-1,cid=-1;
	
	if (app->datum_active_threads < app->max_threads) {
		// we have not launched all threads yet, or somehow a thread has become inactive
		// place this connection on it's own new thread
		
		// let's assume, for now, that if we don't have all threads active that we're not above max_clients
		
		// find the first inactive thread
		for(i=0;i<app->max_threads;i++) {
			// safe to read this without locking, as we're the only one that should be updating it
			if (!app->datum_threads[i].is_active) {
				tid = i;
				break;
			}
		}
		
		if (tid == -1) {
			DLOG_ERROR("Possible bug in thread handler. Could not find an inactive thread. datum_active_threads = %d; max_threads = %d", app->datum_active_threads, app->max_threads);
			return 0;
		}
		
		// clean up thread starting data
		clean_thread_data(&app->datum_threads[tid], app);
		
		app->datum_threads[tid].thread_id = tid;
		app->datum_threads[tid].is_active = true;
		
		if (pthread_create(&app->datum_threads[i].pthread, NULL, datum_threadpool_thread, &app->datum_threads[i]) != 0) {
			DLOG_ERROR("Could not start new thread for TID %d", tid);
			return 0;
		}
		app->datum_active_threads++;
	} else {
		// active threads are maxed already.  find one with the fewest clients
		// in general, it should be safe to read the client count without locking, since
		// we don't particularly care _right here_ if it's higher than expected from a client
		// disconnection.  We're the only one that increments it.
		
		// TODO: Profile if locking/unlocking here is sufficiently slow to care or not on the performance side
		// We don't want to make a clean path to a DoS, even though this is intended as a local service for local miners.
		
		j = app->max_clients_thread;
		
		// find the thread with the lowest client count
		// also tally up the total clients
		for(i=0;i<app->max_threads;i++) {
			if (app->datum_threads[i].connected_clients < j) {
				j = app->datum_threads[i].connected_clients;
				tid = i;
			}
			tc+=app->datum_threads[i].connected_clients;
		}
		
		if (tid == -1) {
			DLOG_INFO("All threads have max clients! Rejecting connection. :(");
			return 0;
		}
		
		if (tc >= app->max_clients) {
			DLOG_INFO("Sum of clients on all threads at configured global maximum (%d) Rejecting connection. :(", app->max_clients);
			return 0;
		}
	}
	
	// lock the thread's data for a moment
	ret = pthread_mutex_lock(&app->datum_threads[tid].thread_data_lock);
	if (ret != 0) {
		DLOG_FATAL("Could not lock mutex for thread data on TID %d: %s", tid, strerror(ret));
		panic_from_thread(__LINE__); // Is this panic worthy? should never happen
		return 0;
	}
	
	// sanity check
	if (app->datum_threads[tid].connected_clients >= app->max_clients_thread) {
		pthread_mutex_unlock(&app->datum_threads[tid].thread_data_lock);
		DLOG_ERROR("Attempted to assign client to thread %d, which already has MAX CLIENTS %d >= %d", tid, app->datum_threads[tid].connected_clients, app->max_clients_thread);
		return 0;
	}
	
	// get the client's cid
	cid = app->datum_threads[tid].next_open_client_index;
	
	// sanity check: confirm this cid is usable
	if (app->datum_threads[tid].client_data[cid].fd != 0) {
		DLOG_ERROR("Possible bug: Desync with next_open_client_index.  Expected open client slot @ %d on non-maxed thread %d! (shows fd = %" PRIuPTR ")", cid, tid, (uintptr_t)app->datum_threads[tid].client_data[cid].fd);
		
		// let's try the hard way to find an open slot
		cid = -1;
		for(i=0;i<app->max_clients_thread;i++) {
			if (app->datum_threads[tid].client_data[i].fd == 0) {
				cid = i;
				break;
			}
		}
		
		if (cid != -1) {
			DLOG_ERROR("Possible bug: Found an open client slot the hard way. Recovering. TID=%d CID=%d", tid, cid);
		} else {
			DLOG_ERROR("Possible bug: Could not find an open client slot the hard way! Rejecting client for TID=%d (%d clients)", tid, app->datum_threads[tid].connected_clients);
			pthread_mutex_unlock(&app->datum_threads[tid].thread_data_lock);
			return 0;
		}
	}
	
	// prep the next open CID by finding the next open slot
	app->datum_threads[tid].next_open_client_index = cid + 1;
	if (app->datum_threads[tid].next_open_client_index == app->max_clients_thread) app->datum_threads[tid].next_open_client_index = 0;
	
	// prep the next open CID
	for(i=app->datum_threads[tid].next_open_client_index; i != cid;) {
		if (app->datum_threads[tid].client_data[i].fd == 0) {
			// i is good
			app->datum_threads[tid].next_open_client_index = i;
			break;
		}
		
		// loop i around
		i++;
		if (i >= app->max_clients_thread) i = 0;
	}
	
	if (i == cid) {
		// we couldn't find an open client slot for the next client :(
		DLOG_DEBUG("Placing client on maxed out thread TID=%d CID=%d ... Thread is now FULL!",tid,cid);
		app->datum_threads[tid].next_open_client_index = app->max_clients_thread-1;
	}
	
	// bump connected client count
	app->datum_threads[tid].connected_clients++;
	
	// clear up and prep slot's client data without clobbering app_client_data
	app->datum_threads[tid].client_data[cid].fd = fd;
	app->datum_threads[tid].client_data[cid].cid = cid;
	app->datum_threads[tid].client_data[cid].new_connection = true;
	app->datum_threads[tid].client_data[cid].datum_thread = (void *)&app->datum_threads[tid];
	app->datum_threads[tid].client_data[cid].in_buf = 0;
	app->datum_threads[tid].client_data[cid].out_buf = 0;
	app->datum_threads[tid].has_new_clients = true;
	
	pthread_mutex_unlock(&app->datum_threads[tid].thread_data_lock);
	
	if (!tc) {
		// tally clients for our debug
		for(i=0;i<app->max_threads;i++) {
			tc+=app->datum_threads[i].connected_clients;
		}
	} else {
		tc++;
	}
	
	strncpy(app->datum_threads[tid].client_data[cid].rem_host, remote_ip, DATUM_MAX_IP_LEN);
	app->datum_threads[tid].client_data[cid].rem_host[DATUM_MAX_IP_LEN] = 0;
	
	DLOG_DEBUG("New client (%s) on TID %d, CID %d with fd %" PRIuPTR ". clients: %d / clients on thread: %d", app->datum_threads[tid].client_data[cid].rem_host, tid, cid, (uintptr_t)fd, tc, app->datum_threads[tid].connected_clients);
	DLOG_DEBUG("app->datum_threads[tid].next_open_client_index = %d", app->datum_threads[tid].next_open_client_index);
	return 1;
}

const char *datum_sockets_setup_listen_sock(const datum_socket_t listen_sock, const struct sockaddr * const sa, const size_t sa_len) {
	if (DATUM_INVALID_SOCKET == listen_sock) {
		return "Could not create listening socket";
	}
	
	datum_socket_setoptions(listen_sock);
	
	static const int reuse = 1;
	if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
		return "setsockopt(SO_REUSEADDR) failed";
	}
	
	if (bind(listen_sock, sa, (int)sa_len) < 0) {
		return "bind failed";
	}
	
	if (listen(listen_sock, 10) < 0) {
		return "listen failed";
	}
	
	return NULL;
}

bool datum_sockets_setup_listening_sockets(const char * const purpose, const char * const addr, const uint16_t port, datum_socket_t * const out_socks, size_t * const inout_socks_n) {
	assert(*inout_socks_n > 0);
	if (addr && addr[0]) {
		char port_str[6];
		snprintf(port_str, sizeof(port_str), "%u", (unsigned int)port);
		const struct addrinfo hints = {
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = 0,
			.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV,
		};
		struct addrinfo *res;
		int err = getaddrinfo(addr, port_str, &hints, &res);
		if (err) {
			DLOG_FATAL("Failed to resolve listen address '%s' (%s): %s", purpose, addr, gai_strerror(err));
			panic_from_thread(__LINE__);
			return false;
		}
		*out_socks = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		const char *errstr = datum_sockets_setup_listen_sock(*out_socks, res->ai_addr, res->ai_addrlen);
		const int errno_saved = errno;
		freeaddrinfo(res);
		if (errstr) {
			DLOG_FATAL("%s (%s): %s", errstr, purpose, strerror(errno_saved));
			panic_from_thread(__LINE__);
			return false;
		}
		*inout_socks_n = 1;
	} else {
		const struct sockaddr_in6 anyaddr6 = {
			.sin6_family = AF_INET6,
			.sin6_port = htons(port),
			.sin6_addr = IN6ADDR_ANY_INIT,
		};
		out_socks[0] = socket(AF_INET6, SOCK_STREAM, 0);
#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
		if (out_socks[0] != DATUM_INVALID_SOCKET) {
			static const int zero = 0;
			setsockopt(out_socks[0], IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&zero, sizeof(zero));
		}
#endif
		const char * const errstr6 = datum_sockets_setup_listen_sock(out_socks[0], (const struct sockaddr *)&anyaddr6, sizeof(anyaddr6));
		const int errno6 = errno;
		unsigned int socks_n = 1;
		if (errstr6 && out_socks[0] != DATUM_INVALID_SOCKET) {
			datum_socket_close(out_socks[0]);
			out_socks[0] = DATUM_INVALID_SOCKET;
			--socks_n;
		}
		
		if (*inout_socks_n > socks_n) {
			const struct sockaddr_in anyaddr4 = {
				.sin_family = AF_INET,
				.sin_port = htons(port),
				.sin_addr.s_addr = INADDR_ANY,
			};
			out_socks[socks_n] = socket(AF_INET, SOCK_STREAM, 0);
			const char *errstr = datum_sockets_setup_listen_sock(out_socks[socks_n], (const struct sockaddr *)&anyaddr4, sizeof(anyaddr4));
			if (errstr && errstr6) {
				const int errno4 = errno;
				DLOG_FATAL("%s (IPv6): %s", errstr6, strerror(errno6));
				DLOG_FATAL("%s (IPv4): %s", errstr, strerror(errno4));
				panic_from_thread(__LINE__);
				return false;
			}
			if (errstr && out_socks[socks_n] != DATUM_INVALID_SOCKET) {
				datum_socket_close(out_socks[socks_n]);
				out_socks[socks_n] = DATUM_INVALID_SOCKET;
			} else {
				++socks_n;
			}
		}
		
		*inout_socks_n = socks_n;
	}
	return true;
}

void *datum_gateway_listener_thread(void *arg) {
	int i, ret;
	bool rejecting_now = false;
	uint64_t last_reject_msg_tsms = 0, curtime_tsms = 0;
	uint64_t reject_count = 0;
	
	T_DATUM_SOCKET_APP *app = (T_DATUM_SOCKET_APP *)arg;
	
	datum_pollfd pollfds[2];
	datum_socket_t listen_socks[2], conn_sock;
	int nfds;
	
	if (!app) {
		DLOG_FATAL("Called without application data structure. :(");
		panic_from_thread(__LINE__);
		return NULL;
	}
	
	DLOG_DEBUG("Setting up app '%s' on address %s port %d. (T:%d/TC:%d/C:%d)", app->name, datum_config.stratum_v1_listen_addr[0] ? datum_config.stratum_v1_listen_addr : "(any)", app->listen_port, app->max_threads, app->max_clients_thread, app->max_clients);
	
	// we assume the caller sets up the thread data in some way
	// don't clobber those pointers
	for(i=0;i<app->max_threads;i++) {
		ret = pthread_mutex_init(&app->datum_threads[i].thread_data_lock, NULL);
		if (ret) {
			DLOG_FATAL("Could not init mutex for thread data: %s", strerror(ret));
			panic_from_thread(__LINE__);
			return NULL;
		}
		
		// set app data pointer
		app->datum_threads[i].app = app;
		app->datum_threads[i].thread_id = i;
		app->datum_threads[i].connected_clients = 0;
		app->datum_threads[i].next_open_client_index = 0;
	}
	
	app->datum_active_threads = 0;
	
	size_t listen_socks_len = 2;
	if (!datum_sockets_setup_listening_sockets("stratum", datum_config.stratum_v1_listen_addr, app->listen_port, listen_socks, &listen_socks_len)) {
		return NULL;
	}
	if (listen_socks_len < 2) listen_socks[1] = DATUM_INVALID_SOCKET;
	for (i = 0; i < (int)listen_socks_len; ++i) {
		pollfds[i].fd = listen_socks[i];
		pollfds[i].events = DATUM_POLLIN;
		pollfds[i].revents = 0;
	}
	
	DLOG_INFO("DATUM Socket listener thread active for '%s'", app->name);
	
	while (!datum_embedded_should_stop()) {
		nfds = datum_poll(pollfds, (unsigned long)listen_socks_len, 100);
		if (nfds) {
			if (datum_config.datum_pooled_mining_only && (!datum_protocol_is_active())) {
				curtime_tsms = current_time_millis(); // we only need this if we're rejecting connections
				if (!rejecting_now) {
					last_reject_msg_tsms = curtime_tsms - 5000; // first disconnect triggers msg
				}
				rejecting_now = true;
			} else {
				rejecting_now = false;
			}
		}
		if (nfds <= 0) continue;
		for (int n = 0; n < (int)listen_socks_len; ++n) {
			if (pollfds[n].revents & DATUM_POLLIN) {
				conn_sock = accept(pollfds[n].fd, NULL, NULL);
				if (conn_sock == DATUM_INVALID_SOCKET) {
					DLOG_ERROR("accept failed: %s", strerror(errno));
					continue;
				}
				
				if (rejecting_now) {
					reject_count++;
					if ((curtime_tsms - last_reject_msg_tsms) > 5000) {
						DLOG_INFO("DATUM not connected and configured for pooled mining only! Rejecting connection. (%llu connections rejected since last noted)", (unsigned long long)reject_count);
						last_reject_msg_tsms = curtime_tsms;
						reject_count = 0;
					}
					datum_socket_close(conn_sock);
					continue;
				}
				
				DLOG_DEBUG("Accepted socket to fd %" PRIuPTR, (uintptr_t)conn_sock);
				datum_socket_setoptions(conn_sock);
				
				// assign socket to a thread
				i = assign_to_thread(app, conn_sock);
				if (!i) {
					// error finding a thread (too many connections?)
					DLOG_DEBUG("Closing socket we couldn't assign %" PRIuPTR, (uintptr_t)conn_sock);
					datum_socket_close(conn_sock);
				}
			}
		}
	}
	for (i = 0; i < 2; ++i) if (listen_socks[i] != DATUM_INVALID_SOCKET) datum_socket_close(listen_socks[i]);
	
	return NULL;
}

void datum_socket_setoptions(datum_socket_t sock) {
	int flag = 1;
	
	if (datum_socket_set_nonblocking(sock) < 0) {
		DLOG_FATAL("failed to set nonblocking socket mode");
		panic_from_thread(__LINE__);
	}
	
	// Set the TCP_NODELAY option
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) < 0) {
		DLOG_FATAL("setsockopt(TCP_NODELAY) failed: %s", strerror(errno));
		panic_from_thread(__LINE__);
	}
}

int datum_socket_send_string_to_client(T_DATUM_CLIENT_DATA *c, char *s) {
	int len = strlen(s);
	if (!len) return 0;
	if ((c->out_buf + len) >= CLIENT_BUFFER) return -1;
	strncpy(&c->w_buffer[c->out_buf], s, CLIENT_BUFFER-(c->out_buf)-1);
	c->out_buf += len;
	return len;
}

int datum_socket_send_chars_to_client(T_DATUM_CLIENT_DATA *c, char *s, int len) {
	if (!len) return 0;
	if ((c->out_buf + len) >= CLIENT_BUFFER) return -1;
	if (len > (CLIENT_BUFFER-(c->out_buf)-1)) {
		len = CLIENT_BUFFER-(c->out_buf)-1;
	}
	memcpy(&c->w_buffer[c->out_buf], s, len);
	c->out_buf += len;
	return len;
}
