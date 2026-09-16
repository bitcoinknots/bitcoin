// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SHAREPOOL_RETRY_WORKER_H
#define BITCOIN_SHAREPOOL_RETRY_WORKER_H

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

namespace sharepool {
struct RetryWorkerStats {
    bool started{false};
    bool active{false};
    bool pending{false};
    bool stopping{false};
    uint64_t requests{0};
    uint64_t passes{0};
    uint64_t failures{0};
    int64_t last_micros{0};
    int64_t max_micros{0};
};

/** One lifecycle-owned worker and one coalesced notification, never a queue of
 * untrusted payloads. Work owns its existing separately bounded durable queue.
 * Requests before Start or during an active pass are retained. The mutex is
 * never held during work, error reporting or joining the thread.
 * Start/Stop are serialized by the owning application's lifecycle.
 */
class RetryWorker {
    using Clock = std::chrono::steady_clock;
    const std::function<void(const std::atomic<bool>&)> m_work;
    const std::function<void(std::exception_ptr)> m_error;
    const Clock::duration m_minimum_pause;
    const unsigned m_pause_factor;
    mutable std::mutex m_mutex;
    std::condition_variable m_wake;
    std::thread m_thread;
    std::atomic<bool> m_stopping{false};
    RetryWorkerStats m_stats;

    void Run()
    {
        Clock::time_point next{};
        std::unique_lock lock{m_mutex};
        while (true) {
            m_wake.wait(lock, [&] { return m_stopping || m_stats.pending; });
            if (m_stopping) break;
            if (Clock::now() < next) {
                m_wake.wait_until(lock, next, [&] { return m_stopping.load(); });
                if (m_stopping) break;
            }
            m_stats.pending = false;
            m_stats.active = true;
            lock.unlock();
            const auto began = Clock::now();
            std::exception_ptr error;
            try { m_work(m_stopping); }
            catch (...) { error = std::current_exception(); }
            const auto elapsed = Clock::now() - began;
            if (error && m_error) m_error(error);
            lock.lock();
            m_stats.active = false;
            ++m_stats.passes;
            m_stats.failures += bool(error);
            m_stats.last_micros = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
            m_stats.max_micros = std::max(m_stats.max_micros, m_stats.last_micros);
            next = Clock::now() + std::max(m_minimum_pause, elapsed * m_pause_factor);
        }
        m_stats.active = false;
        m_stats.pending = false;
    }

public:
    RetryWorker(std::function<void(const std::atomic<bool>&)> work,
                std::function<void(std::exception_ptr)> error,
                Clock::duration minimum_pause = std::chrono::milliseconds{50}, unsigned pause_factor = 4)
        : m_work{std::move(work)}, m_error{std::move(error)},
          m_minimum_pause{minimum_pause}, m_pause_factor{pause_factor} {}

    ~RetryWorker() { Stop(); }
    RetryWorker(const RetryWorker&) = delete;
    RetryWorker& operator=(const RetryWorker&) = delete;

    void Start()
    {
        std::lock_guard lock{m_mutex};
        if (m_stats.started || m_stopping) return;
        m_thread = std::thread([this] { Run(); });
        m_stats.started = true;
    }

    bool Request()
    {
        {
            std::lock_guard lock{m_mutex};
            if (m_stopping) return false;
            ++m_stats.requests;
            m_stats.pending = true;
        }
        m_wake.notify_one();
        return true;
    }

    void Stop()
    {
        m_stopping = true;
        m_wake.notify_all();
        if (m_thread.joinable()) m_thread.join();
        std::lock_guard lock{m_mutex};
        m_stats.pending = false;
        m_stats.stopping = true;
    }

    RetryWorkerStats Stats() const
    {
        std::lock_guard lock{m_mutex};
        auto stats = m_stats;
        stats.stopping = m_stopping;
        return stats;
    }
};
} // namespace sharepool
#endif // BITCOIN_SHAREPOOL_RETRY_WORKER_H
