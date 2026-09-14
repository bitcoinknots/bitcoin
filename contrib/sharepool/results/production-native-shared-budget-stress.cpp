// Standalone sanitizer/fault harness; no runtime allocator hook is added to the node.
#include <sharepool/hash_validation_cache.h>
#include <array>
#include <atomic>
#include <cassert>
#include <cstdlib>
#include <future>
#include <iostream>
#include <limits>
#include <new>
#include <thread>
#include <vector>

namespace {
thread_local bool fail_next_allocation{false};
thread_local sharepool::DecodedSnapshotRetentionBudget* observed_budget{nullptr};
thread_local size_t expected_reserved_bytes{0};
}

void* operator new(std::size_t bytes)
{
    if (fail_next_allocation) {
        fail_next_allocation = false;
        assert(observed_budget && observed_budget->Bytes() == expected_reserved_bytes);
        throw std::bad_alloc{};
    }
    if (auto* allocation = std::malloc(bytes ? bytes : 1)) return allocation;
    throw std::bad_alloc{};
}
void* operator new[](std::size_t bytes) { return ::operator new(bytes); }
void operator delete(void* allocation) noexcept { std::free(allocation); }
void operator delete[](void* allocation) noexcept { std::free(allocation); }
void operator delete(void* allocation, std::size_t) noexcept { std::free(allocation); }
void operator delete[](void* allocation, std::size_t) noexcept { std::free(allocation); }

int main()
{
    using namespace sharepool;
    const auto snapshot = std::make_shared<const hashonly::Snapshot>();
    const auto charge = DecodedSnapshotCacheCharge(*snapshot, 512);
    auto budget = std::make_shared<DecodedSnapshotRetentionBudget>(3 * charge);
    {
        DecodedSnapshotCache cache{2 * charge, 1, budget};
        // Empty snapshots need no allocations in the charge walk. The next
        // allocation is the actual map insertion, after its lease is acquired.
        observed_budget = budget.get();
        expected_reserved_bytes = charge;
        fail_next_allocation = true;
        assert(!cache.Put(uint256{uint8_t{1}}, snapshot, 512));
        assert(!fail_next_allocation && budget->Bytes() == 0);
        assert(cache.Bytes() == 0 && cache.Size() == 0 && snapshot);
        assert(cache.Put(uint256{uint8_t{1}}, snapshot, 512));
        assert(budget->Bytes() == charge);
    }
    assert(budget->Bytes() == 0);
    constexpr size_t THREADS{8};
    std::promise<void> release;
    const auto released = release.get_future().share();
    std::array<std::promise<void>, THREADS> entered;
    std::vector<std::future<void>> workers;
    std::atomic<size_t> admitted{0};
    for (size_t thread{0}; thread < THREADS; ++thread) {
        workers.push_back(std::async(std::launch::async, [&, thread] {
            DecodedSnapshotCache cache{2 * charge, 1, budget};
            if (cache.Put(uint256{uint8_t{1}}, snapshot, 512)) ++admitted;
            entered[thread].set_value();
            released.wait();
            for (size_t i{0}; i < 10000; ++i) {
                cache.Put(uint256{static_cast<uint8_t>(i % 3 + 1)}, snapshot, 512);
                assert(budget->Bytes() <= 3 * charge && cache.Bytes() <= charge);
                if (i % 16 == 0) std::this_thread::yield();
            }
        }));
    }
    for (auto& ready : entered) ready.get_future().wait();
    assert(admitted.load() == 3 && budget->Bytes() == 3 * charge);
    release.set_value();
    for (auto& worker : workers) worker.get();
    assert(budget->Bytes() == 0);
    std::cout << "passed: actual Put allocation failure releases lease and retains caller value; "
                 "8 threads x 10000 insert/evict attempts; aggregate ceiling respected; final charge zero\n";
}
