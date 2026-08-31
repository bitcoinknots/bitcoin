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
 * Copyright (c) 2024 Bitcoin Ocean, LLC & Jason Hughes
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

#ifndef _DATUM_SOCKETS_H_
#define _DATUM_SOCKETS_H_

#ifndef T_DATUM_TEMPLATE_DATA
	#include "datum_blocktemplates.h"
#endif

#include <stdint.h>
#include <stdatomic.h>
#include "datum_net.h"
#include "datum_thread.h"

typedef struct T_DATUM_THREAD_DATA T_DATUM_THREAD_DATA;
typedef struct T_DATUM_CLIENT_DATA T_DATUM_CLIENT_DATA;

typedef void (*DATUM_ThreadPool_Init_Func)(T_DATUM_THREAD_DATA *);
typedef void (*DATUM_ThreadPool_Loop_Func)(T_DATUM_THREAD_DATA *);
typedef int (*DATUM_ThreadPool_ClientCmd_Func)(T_DATUM_CLIENT_DATA *, char *);

typedef void (*DATUM_ThreadPool_ClientClosed_Func)(T_DATUM_CLIENT_DATA *, const char *);
typedef void (*DATUM_ThreadPool_ClientNew_Func)(T_DATUM_CLIENT_DATA *);

#define DATUM_MAX_IP_LEN 64

// TODO: Make these dynamic
// These are hard coded buffer related values, not directly related to the config file values.
// We avoid dynamic memory allocation to prevent fragmentation and other hassles, currently.
#define MAX_CLIENTS_THREAD 4096
#define MAX_THREADS 64
#define MAX_EVENTS (MAX_CLIENTS_THREAD*2)

typedef struct T_DATUM_CLIENT_DATA {
	bool new_connection;
	_Atomic(datum_socket_t) fd;
	int cid;
	
	char buffer[CLIENT_BUFFER];
	int in_buf;
	
	char w_buffer[CLIENT_BUFFER];
	int out_buf;
	
	char rem_host[DATUM_MAX_IP_LEN+1];
	
	bool kill_request;
	
	void *app_client_data;
	
	int proxy_line_read;
	
	T_DATUM_THREAD_DATA *datum_thread;
} T_DATUM_CLIENT_DATA;

typedef struct {
	char name[32];
	
	// Called when a new threadpool thread is started
	DATUM_ThreadPool_Init_Func init_func;
	
	// Called at the beginning of each loop of the threadpool thread
	DATUM_ThreadPool_Loop_Func loop_func;
	
	// Called for each command the threadpool thread receives from a client
	DATUM_ThreadPool_ClientCmd_Func client_cmd_func;
	
	// Called each time a client is disconnected (either on purpose or via an error)
	DATUM_ThreadPool_ClientClosed_Func closed_client_func;
	
	// Called each time a new client connects and is assigned to a threadpool thread
	DATUM_ThreadPool_ClientNew_Func new_client_func;
	
	// TCP port this server will listen on
	int listen_port;
	
	// Maximum clients each thread can handle
	int max_clients_thread;
	
	// Maximum threads in the thread pool for this server
	int max_threads;
	
	// Maximum number of total clients for the server
	int max_clients;
	
	// Memory allocated by the app before starting the listener for max_threads worth of thread data
	// TODO: Dynamically allocate client_data and events
	T_DATUM_THREAD_DATA *datum_threads;
	
	int datum_active_threads;
} T_DATUM_SOCKET_APP;

typedef struct {
	// app functions and global data for socket app
	T_DATUM_SOCKET_APP *config;
	
	// application specific data for this thread
	void *data;
} T_DATUM_SOCKET_APP_THREAD_DATA;

typedef struct T_DATUM_THREAD_DATA {
	pthread_t pthread;
	
	bool is_active;
	
	bool has_new_clients;
	
	bool empty_request;
	bool has_client_kill_request;
	
	int thread_id;
	//int newBlockCount;
	
	// Sized from the configured per-thread client limit by the embedded wrapper.
	T_DATUM_CLIENT_DATA *client_data;
	
	pthread_mutex_t thread_data_lock;
	
	int connected_clients;
	int next_open_client_index;
	
	datum_pollfd *pollfds;
	int *poll_client_ids;
	// information for this socket application
	// this is global to the socket application
	T_DATUM_SOCKET_APP *app;
	
	// Socket application data for threadpool
	// remember, this is per thread
	void *app_thread_data;
} T_DATUM_THREAD_DATA;

bool datum_sockets_setup_listening_sockets(const char *purpose, const char *addr, uint16_t port, datum_socket_t *out_socks, size_t *inout_socks_n);
void *datum_gateway_listener_thread(void *arg);
void datum_socket_setoptions(datum_socket_t sock);

int datum_socket_send_string_to_client(T_DATUM_CLIENT_DATA *c, char *s);
int datum_socket_send_chars_to_client(T_DATUM_CLIENT_DATA *c, char *s, int len);

int assign_to_thread(T_DATUM_SOCKET_APP *app, datum_socket_t fd);
void *datum_threadpool_thread(void *arg);

static inline void datum_socket_thread_client_count_decrement(T_DATUM_THREAD_DATA *my, int cid_who_left, bool not_already_locked) {
	// compiler will optimize the if's away in most cases, since this is inline
	if (not_already_locked) pthread_mutex_lock(&my->thread_data_lock);
	
	// decrement connected client count for the thread
	my->connected_clients--;
	
	// if the ID we dropped is less than the expected next, drop it down to speed that up
	if (cid_who_left < my->next_open_client_index) {
		my->next_open_client_index = cid_who_left;
	}
	my->client_data[cid_who_left].fd = 0;
	if (not_already_locked) pthread_mutex_unlock(&my->thread_data_lock);
}

#endif
