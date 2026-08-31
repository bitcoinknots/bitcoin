/* Copyright (c) 2026 The Bitcoin Purity developers
 * Distributed under the MIT software license. */
#ifndef BITCOINPURITY_DATUM_THREAD_H
#define BITCOINPURITY_DATUM_THREAD_H

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>

typedef HANDLE pthread_t;
typedef SRWLOCK pthread_mutex_t;
typedef SRWLOCK pthread_rwlock_t;
typedef CONDITION_VARIABLE pthread_cond_t;

#define PTHREAD_MUTEX_INITIALIZER SRWLOCK_INIT
#define PTHREAD_RWLOCK_INITIALIZER SRWLOCK_INIT
#define PTHREAD_COND_INITIALIZER CONDITION_VARIABLE_INIT

struct datum_thread_start {
    void *(*fn)(void *);
    void *arg;
};

static inline DWORD WINAPI datum_thread_entry(void *opaque)
{
    struct datum_thread_start *start = opaque;
    void *(*fn)(void *) = start->fn;
    void *arg = start->arg;
    free(start);
    fn(arg);
    return 0;
}

static inline int pthread_create(pthread_t *thread, const void *attr, void *(*fn)(void *), void *arg)
{
    (void)attr;
    struct datum_thread_start *start = malloc(sizeof(*start));
    if (!start) return 1;
    start->fn = fn;
    start->arg = arg;
    *thread = CreateThread(NULL, 0, datum_thread_entry, start, 0, NULL);
    if (!*thread) {
        free(start);
        return 1;
    }
    return 0;
}

static inline int pthread_join(pthread_t thread, void **result)
{
    (void)result;
    if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) return 1;
    CloseHandle(thread);
    return 0;
}

static inline int pthread_mutex_init(pthread_mutex_t *mutex, const void *attr) { (void)attr; InitializeSRWLock(mutex); return 0; }
static inline int pthread_mutex_lock(pthread_mutex_t *mutex) { AcquireSRWLockExclusive(mutex); return 0; }
static inline int pthread_mutex_trylock(pthread_mutex_t *mutex) { return TryAcquireSRWLockExclusive(mutex) ? 0 : 1; }
static inline int pthread_mutex_unlock(pthread_mutex_t *mutex) { ReleaseSRWLockExclusive(mutex); return 0; }
static inline int pthread_rwlock_init(pthread_rwlock_t *lock, const void *attr) { (void)attr; InitializeSRWLock(lock); return 0; }
static inline int pthread_rwlock_rdlock(pthread_rwlock_t *lock) { AcquireSRWLockExclusive(lock); return 0; }
static inline int pthread_rwlock_wrlock(pthread_rwlock_t *lock) { AcquireSRWLockExclusive(lock); return 0; }
static inline int pthread_rwlock_unlock(pthread_rwlock_t *lock) { ReleaseSRWLockExclusive(lock); return 0; }
static inline int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) { return SleepConditionVariableSRW(cond, mutex, INFINITE, 0) ? 0 : 1; }
static inline int pthread_cond_signal(pthread_cond_t *cond) { WakeConditionVariable(cond); return 0; }
static inline int pthread_cond_broadcast(pthread_cond_t *cond) { WakeAllConditionVariable(cond); return 0; }

#else
#include <pthread.h>
#endif

#endif
