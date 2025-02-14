#include "flashws/utils/flash_alloc.h"
#include <chrono>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>

// Helper class for time measurement
class Timer {
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = Clock::time_point;
    TimePoint start_;
public:
    Timer() : start_(Clock::now()) {}

    double elapsed() const {
        auto now = Clock::now();
        return std::chrono::duration<double, std::milli>(now - start_).count();
    }
};

// Test configuration
struct TestConfig {
    size_t num_ops;             // Total "operations" (alloc or free) to perform
    size_t min_size;
    size_t max_size;

    bool mixed_ops;             // Whether we do interleaved allocations & frees
    double alloc_probability;   // Probability of "allocate" vs "free"
    bool include_final_free;    // Whether to include time of final bulk free in the measurement
};

// A lightweight pseudo-random generator for reproducible tests
class FastRand {
private:
    uint64_t state_;
public:
    explicit FastRand(uint64_t seed = 123456789ULL) : state_(seed) {}

    // Returns a 64-bit pseudo-random integer
    uint64_t next() {
        // Simple LCG parameters
        state_ = 2862933555777941757ULL * state_ + 3037000493ULL;
        return state_;
    }

    // Returns a random size in [min_val, max_val]
    size_t next_size_t(size_t min_val, size_t max_val) {
        // Grab top bits from next() to produce uniform range
        uint64_t r = next();
        return static_cast<size_t>(r % (max_val - min_val + 1)) + min_val;
    }

    // Returns true w/ probability p
    bool next_bool(double p) {
        // Use top 53 bits to generate a double in [0,1)
        constexpr double factor = (1.0 / (1ULL << 53));
        double rnd_d = static_cast<double>(next() >> 11) * factor;
        return (rnd_d < p);
    }
};

// Standard allocator wrapper class
class StdAllocator {
public:
    void* allocate(size_t n) {
        return std::malloc(n);
    }

    void deallocate(void* p) {
        std::free(p);
    }
};

// Flash allocator wrapper class
class FlashAllocWrapper {
    fws::MemPool pool_;
public:
    void* allocate(size_t n) {
        return pool_.allocate(n);
    }

    void deallocate(void* p) {
        pool_.deallocate(p);
    }
};

/**
 * Runs an "interleaved" allocation test (mixed allocate/free ops).
 * Returns a tuple of:
 *   (total_time_in_ms, global_sum_of_data, final_bytes_live)
 */
template<typename Allocator>
std::tuple<double, uint64_t, uint64_t>
run_mixed_alloc_test(const TestConfig& config, Allocator& alloc)
{
    Timer timer;

    // Fixed seed for reproducibility
    FastRand rng(12345ULL);

    // {ptr, size} for active allocations
    std::vector<std::pair<void*, size_t>> activePtrs;
    activePtrs.reserve(config.num_ops);

    uint64_t global_sum = 0;  // sum of all data we read on free
    uint64_t cur_bytes = 0;   // track how many bytes are currently allocated

    for (size_t i = 0; i < config.num_ops; i++) {
        bool doAlloc = rng.next_bool(config.alloc_probability);

        // If we have no active allocations, we must allocate
        if (activePtrs.empty()) {
            doAlloc = true;
        }

        if (doAlloc) {
            // Allocate
            size_t sz = rng.next_size_t(config.min_size, config.max_size);
            cur_bytes += sz;
            void* ptr = alloc.allocate(sz);

            // Write data (simple) to avoid compiler optimizations
            std::memset(ptr, -1, sz);

            // Store in active list
            activePtrs.emplace_back(ptr, sz);
        } else {
            // Free a random one
            size_t idx = rng.next_size_t(0, activePtrs.size() - 1);

            void* ptr = activePtrs[idx].first;
            size_t sz = activePtrs[idx].second;
            cur_bytes -= sz;

            // Sum data before free
            uint64_t sumLocal = 0;
            const uint64_t* p64 = reinterpret_cast<uint64_t*>(ptr);
            size_t words = sz / sizeof(uint64_t);
            for (size_t w = 0; w < words; w++) {
                sumLocal += p64[w];
            }
            global_sum += sumLocal;

            // Deallocate
            alloc.deallocate(ptr);

            // Erase by swapping last element
            activePtrs[idx] = activePtrs.back();
            activePtrs.pop_back();
        }
    }

    // time before final free
    double timeBeforeFinalFree = timer.elapsed();
    uint64_t final_bytes = cur_bytes;

    // optionally free everything left
    if (config.include_final_free && !activePtrs.empty()) {
        for (auto& kv : activePtrs) {
            void* ptr = kv.first;
            size_t sz = kv.second;

            // sum data
            uint64_t sumLocal = 0;
            const uint64_t* p64 = reinterpret_cast<uint64_t*>(ptr);
            size_t words = sz / sizeof(uint64_t);
            for (size_t w = 0; w < words; w++) {
                sumLocal += p64[w];
            }
            global_sum += sumLocal;

            alloc.deallocate(ptr);
        }
    }
    double totalTime = timer.elapsed();
    if (!config.include_final_free) {
        totalTime = timeBeforeFinalFree;
    }

    return {totalTime, global_sum, final_bytes};
}

/**
 * Runs a *single* test config in this process.
 * Prints the result to stdout.
 */
void run_single_test(const TestConfig& config)
{
    // Print test info
    std::cout << "Test Configuration:\n";
    std::cout << "- Mixed Ops: " << (config.mixed_ops ? "Yes" : "No") << "\n";
    std::cout << "- num_ops: " << config.num_ops << "\n";
    std::cout << "- Size Range: " << config.min_size << " - " << config.max_size << "\n";
    std::cout << "- Alloc Probability: " << config.alloc_probability << "\n";
    std::cout << "- Include final free in timing: "
              << (config.include_final_free ? "Yes" : "No") << "\n\n";


    // We will do the test for StdAllocator and FlashAllocWrapper in this process
    // so that side effects are isolated from other config tests.
    double std_time_ms = 0, flash_time_ms = 0;
    // Standard malloc/free
    {
        StdAllocator std_alloc;
        auto [timeMs, sumVal, finalBytes] = run_mixed_alloc_test(config, std_alloc);
        std::cout << "[StdAllocator] Time: " << timeMs << " ms, Final Bytes: "
                  << finalBytes  / (1024ULL * 1024UL) << " MB, Sum: " << sumVal << "\n";
        std_time_ms = timeMs;
    }

    // Flash Alloc
    {
        FlashAllocWrapper flash_alloc;
        auto [timeMs, sumVal, finalBytes] = run_mixed_alloc_test(config, flash_alloc);
        std::cout << "[FlashAlloc  ] Time: " << timeMs << " ms, Final Mem : "
                  << finalBytes / (1024ULL * 1024UL) << " MB, Sum: " << sumVal << "\n";
        flash_time_ms = timeMs;
    }

    double speedup = std_time_ms / flash_time_ms;
    std::cout << "Speedup: " << std::fixed << std::setprecision(2) << speedup << "x\n";

    std::cout << "--------------------------------------------\n\n";
}

/**
 * Main benchmark function that uses fork() to run
 * each config in its own child process.
 */
void run_benchmark_forked()
{
    // Example configs
    std::vector<TestConfig> configs = {
            {10'000'000, 8, 64, true,  0.7, false},     // test 1
            {1'000'000, 256, 1024, true, 0.7, false},   // test 2
            {100'000, 4096, 16384, true, 0.7, false},   // test 3
    };

    for (size_t i = 0; i < configs.size(); ++i) {
        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "Fork failed for config index " << i << "\n";
            return;
        }

        if (pid == 0) {
            // Child process: run the single test in isolation
            run_single_test(configs[i]);
            // Flush output to ensure it appears in the parent logs
            std::fflush(stdout);

            // Exit so we don't continue in the parent flow
            _exit(0);
        } else {
            // Parent process: just wait for the child to finish
            int status = 0;
            waitpid(pid, &status, 0);

            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (code != 0) {
                    std::cerr << "Child process for config " << i
                              << " exited with code " << code << "\n";
                }
            } else {
                std::cerr << "Child process for config " << i
                          << " did not exit normally.\n";
            }
        }
    }
}

int main()
{
    run_benchmark_forked();
    return 0;
}
