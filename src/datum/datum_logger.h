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

#ifndef _DATUM_LOGGER_H_
#define _DATUM_LOGGER_H_

#include <stdint.h>
#include <stdbool.h>

// approximately this times 3 will be used
// NOTE: With huge debug logging, this CAN potentially overrun and fail
#define DLOG_MSG_BUF_SIZE (1024*1024*8)

typedef struct {
	int level;
	uint64_t tsms;
	char calling_function[48];
	char *msg;
} DLOG_MSG;

#define DLOG_LEVEL_ALL 0
#define DLOG_LEVEL_DEBUG 1
#define DLOG_LEVEL_INFO 2
#define DLOG_LEVEL_WARN 3
#define DLOG_LEVEL_ERROR 4
#define DLOG_LEVEL_FATAL 5

int datum_logger_queue_msg(const char *func, int level, const char *format, ...)
#ifndef _MSC_VER
    __attribute__((format(printf, 3, 4)))
#endif
    ;

// Generic for dynamic log level messages
#define DLOG(level, format, ...) datum_logger_queue_msg(__func__, level, format __VA_OPT__(,) __VA_ARGS__)

// for leftover logging code, default to debug level
#define LOG_PRINTF(format, ...) datum_logger_queue_msg(__func__, DLOG_LEVEL_DEBUG, format __VA_OPT__(,) __VA_ARGS__)

// macros for various log levels
#define DLOG_DEBUG(format, ...) datum_logger_queue_msg(__func__, DLOG_LEVEL_DEBUG, format __VA_OPT__(,) __VA_ARGS__)
#define DLOG_INFO(format, ...) datum_logger_queue_msg(__func__, DLOG_LEVEL_INFO, format __VA_OPT__(,) __VA_ARGS__)
#define DLOG_WARN(format, ...) datum_logger_queue_msg(__func__, DLOG_LEVEL_WARN, format __VA_OPT__(,) __VA_ARGS__)
#define DLOG_ERROR(format, ...) datum_logger_queue_msg(__func__, DLOG_LEVEL_ERROR, format __VA_OPT__(,) __VA_ARGS__)
#define DLOG_FATAL(format, ...) datum_logger_queue_msg(__func__, DLOG_LEVEL_FATAL, format __VA_OPT__(,) __VA_ARGS__)

int datum_logger_init(void);
void datum_logger_config(
	bool clog_to_file,
	bool clog_to_console,
	int clog_level_console,
	int clog_level_file,
	bool clog_calling_function,
	bool clog_to_stderr,
	bool clog_rotate_daily,
	char *clog_file
);

#endif
