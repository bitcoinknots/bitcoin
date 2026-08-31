/* Bitcoin Purity logging adapter for upstream-derived DATUM C code. */
#include "datum_embedded.h"
#include "datum_logger.h"

#include <stdarg.h>
#include <stdio.h>

int datum_logger_queue_msg(const char* func, int level, const char* format, ...)
{
    char body[4096];
    char message[4200];
    va_list args;
    va_start(args, format);
    vsnprintf(body, sizeof(body), format, args);
    va_end(args);
    snprintf(message, sizeof(message), "%s: %s", func, body);
    datum_bridge_log(level, message);
    if (level == DLOG_LEVEL_FATAL) datum_bridge_fatal_error(message);
    return 0;
}

int datum_logger_init(void) { return 0; }

void datum_logger_config(bool clog_to_file, bool clog_to_console, int clog_level_console,
    int clog_level_file, bool clog_calling_function, bool clog_to_stderr,
    bool clog_rotate_daily, char* clog_file)
{
    (void)clog_to_file;
    (void)clog_to_console;
    (void)clog_level_console;
    (void)clog_level_file;
    (void)clog_calling_function;
    (void)clog_to_stderr;
    (void)clog_rotate_daily;
    (void)clog_file;
}

