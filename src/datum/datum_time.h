/* Copyright (c) 2026 The Bitcoin Purity developers
 * Distributed under the MIT software license. */
#ifndef BITCOINPURITY_DATUM_TIME_H
#define BITCOINPURITY_DATUM_TIME_H

#ifdef _WIN32
#include <windows.h>
static inline void datum_sleep_seconds(unsigned int seconds) { Sleep(seconds * 1000U); }
static inline void datum_sleep_micros(unsigned int micros) { Sleep((micros + 999U) / 1000U); }
#define sleep datum_sleep_seconds
#define usleep datum_sleep_micros
#else
#include <unistd.h>
static inline void datum_sleep_seconds(unsigned int seconds) { sleep(seconds); }
static inline void datum_sleep_micros(unsigned int micros) { usleep(micros); }
#endif

#endif
