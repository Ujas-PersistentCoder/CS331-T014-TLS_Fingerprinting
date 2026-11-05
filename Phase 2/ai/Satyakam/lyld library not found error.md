User: dyld[3425]: Library not loaded: @rpath/libgtest_main.1.11.0.dylib
  Referenced from: <2912DA06-8CFD-3F67-A003-01BE6B21ADE3> /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/build/unit_tests
  Reason: no LC_RPATH's found
CMake Error at /opt/homebrew/share/cmake/Modules/GoogleTestAddTests.cmake:233 (message):
  Error running test executable.

    Path: '/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/build/unit_tests'
    Working directory: '/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/build'
    Timeout: '5'
    Result: Subprocess aborted
    Output:
      

Call Stack (most recent call first):
  unit_tests_e3b0c442_discovery.cmake:2 (gtest_discover_tests_impl)


make[2]: *** [unit_tests] Error 1
make[2]: *** Deleting file `unit_tests'
make[1]: *** [CMakeFiles/unit_tests.dir/all] Error 2
make: *** [all] Error 2 cmake --build build  --parallel I am running this so getting the above bug, fix this

Copilot: I’ll inspect the engine’s CMake test target and current build configuration, then patch the runtime search path in the project rather than relying on environment-specific linker settings.

Search for `gtest|GoogleTest|unit_tests|GTest`

Find files matching `Phase 2/engine/**/CMakeLists.txt`

Ran terminal command: git --no-pager status --short && printf '\n--- build files ---\n' && find 'Phase 2/engine' -maxdepth 2 -type f \( -name 'CMakeCache.txt' -o -name 'Makefile' -o -name 'unit_tests' \) -print

Read , lines 1 to 160
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/CMakeLists.txt",
  "view_range": [
    1,
    160
  ]
}

Ran terminal command: cmake -LA -N build | grep -E 'GTEST|GTest|CMAKE_BUILD_TYPE|CMAKE_OSX' || true; printf '\n--- linked deps if executable exists ---\n'; if [ -e build/unit_tests ]; then otool -L build/unit_tests; fi; printf '\n--- gtest install candidates ---\n'; find /opt/homebrew -name 'libgtest*.dylib' -o -name 'libgtest*.a' 2>/dev/null | head -30

The failure is in CMake test discovery: `unit_tests` links Homebrew’s shared GoogleTest dylib, but the executable has no macOS runtime search path. I’ll confirm the imported library location and apply a target-level RPATH fix that remains portable across the existing GoogleTest discovery/fetch paths.

Search for `BUILD_RPATH|INSTALL_RPATH|CMAKE_INSTALL_RPATH|gtest_discover_tests`

Ran terminal command: cd 'Phase 2/engine' && grep -E 'GTEST|GTest|CMAKE_BUILD_TYPE|CMAKE_OSX' build/CMakeCache.txt || true; if [ -e build/unit_tests ]; then otool -L build/unit_tests; fi; find build -type f \( -name 'libgtest*.dylib' -o -name 'libgtest*.a' \) -print

Ran terminal command: brew --prefix googletest 2>/dev/null || true; find /opt/homebrew /usr/local -path '*gtest*' -type f \( -name '*.dylib' -o -name '*.a' \) 2>/dev/null | head -50

Ran terminal command: cd 'Phase 2/engine' && find build -maxdepth 3 -type f -name '*unit_tests*' -print | sort | head -30; test -f build/CMakeFiles/unit_tests.dir/link.txt && sed -n '1,5p' build/CMakeFiles/unit_tests.dir/link.txt || true

Ran terminal command: cd 'Phase 2/engine' && grep -R -n 'libgtest_main\|gtest_main' build/CMakeFiles/unit_tests.dir build/CMakeFiles/Export build/_deps 2>/dev/null | head -40; printf '\n--- config ---\n'; grep -R -n 'IMPORTED_LOCATION\|libgtest' /opt/anaconda3/lib/cmake/GTest /opt/homebrew/opt/googletest/lib/cmake/GTest 2>/dev/null | head -60

Edit 

The project now derives the runtime path from `GTest::gtest_main` itself, so it covers both Conda/Homebrew shared libraries and the fetched in-tree target without hardcoded machine paths. I’ll reconfigure and build the actual `Phase 2/engine/build` tree to verify test discovery succeeds.

Ran terminal command: cd 'Phase 2/engine' && cmake -S . -B build && cmake --build build --parallel

Ran terminal command: cd 'Phase 2/engine' && otool -l build/unit_tests | grep -A3 LC_RPATH

Ran terminal command: cd 'Phase 2/engine' && ctest --test-dir build --output-on-failure

Read , lines 112 to 140
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/CMakeLists.txt",
  "view_range": [
    112,
    140
  ]
}

Ran terminal command: git --no-pager diff -- 'Phase 2/engine/CMakeLists.txt'; git --no-pager status --short

Fixed in `CMakeLists.txt`.

Added a target-derived macOS `BUILD_RPATH` for GoogleTest shared libraries, allowing `gtest_discover_tests()` to execute `unit_tests`.

Verified:

```text
cmake --build build --parallel  ✅
ctest --test-dir build          ✅
46/46 tests passed
```

Run:

```bash
cd "Phase 2/engine"
cmake -S . -B build
cmake --build build --parallel
```

User: I have 1 concern. I hope that the cmake will work device agnostically, that is on macOS, Windows and LInux all three. 

The second thing is that I need you to completely examine if the multithreading is working properly in the system, mostly we have implemented it only in the capture.cpp and Tell me if there is someting which is broken or some thing which we can improve

Copilot: I’ll verify the CMake change across platform-specific branches, then trace the capture threading lifecycle, shared state, shutdown, and error paths in `capture.cpp` and its callers before reporting concrete issues and improvements.

Read , lines 1 to 320
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    1,
    320
  ]
}

Read , lines 1 to 155
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/CMakeLists.txt",
  "view_range": [
    1,
    155
  ]
}

Read , lines 1 to 260
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/include/capture.hpp",
  "view_range": [
    1,
    260
  ]
}
Tool execution failed: Path does not exist

Search for `Capture|capture_|start_capture|stop_capture|std::thread|mutex|condition_varia...`

The initial review shows the threading model is a producer/worker design with a bounded queue and per-worker flow state. I’m narrowing the audit to queue memory ordering, packet ownership, flow affinity, shutdown, and cross-thread output/database access—the areas most likely to cause silent corruption or hangs.

Read , lines 1 to 130
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/include/tlsfp/capture.hpp",
  "view_range": [
    1,
    130
  ]
}

Read , lines 190 to 680
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    190,
    680
  ]
}

Read , lines 680 to 940
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    680,
    940
  ]
}

Read , lines 1 to 160
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/main.cpp",
  "view_range": [
    1,
    160
  ]
}

Read , lines 1 to 210
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/code/cpp/CMakeLists.txt",
  "view_range": [
    1,
    210
  ]
}

Read , lines 240 to 430
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    240,
    430
  ]
}

Read , lines 430 to 650
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    430,
    650
  ]
}

Read , lines 800 to 933
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    800,
    933
  ]
}

Search for `TwoTierAccumulator|process_segment|dispatch_handshake|dropped_packets|running...`

Read , lines 1 to 230
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp",
  "view_range": [
    1,
    230
  ]
}

Read , lines 1 to 130
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/include/tlsfp/accumulator.hpp",
  "view_range": [
    1,
    130
  ]
}

Read , lines 1 to 220
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/include/tlsfp/db.hpp",
  "view_range": [
    1,
    220
  ]
}

Read , lines 1 to 280
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/db.cpp",
  "view_range": [
    1,
    280
  ]
}

Search for `sqlite|redis|std::unordered_map|mutex|shared_mutex|lookup\(|enroll\(`

Read , lines 440 to 525
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/db.cpp",
  "view_range": [
    440,
    525
  ]
}

Read , lines 618 to 650
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    618,
    650
  ]
}

Search for `#include <(unistd|arpa/inet|netinet|netdb|sys/socket|sys/time)`

Ran terminal command: cd 'Phase 2/engine' && cmake --build build --parallel --verbose 2>&1 | tail -40

## 1. CMake portability

The GoogleTest RPATH fix is safe on macOS and Linux, but it does **not** make the entire project Windows-compatible yet.

### Current status

| Platform | CMake/test status |
|---|---|
| macOS | Works; verified 46/46 tests |
| Linux | The RPATH approach is valid |
| Windows | Project source currently has POSIX-only headers/API usage |

Windows compatibility is currently blocked by files such as:

- `capture.cpp`
- `db.cpp`
- `main.cpp`
- `types.hpp`

They use POSIX-specific headers such as:

```cpp
<unistd.h>
<arpa/inet.h>
<netinet/ip.h>
<sys/socket.h>
<netdb.h>
```

The CMake file already links `ws2_32`, but the source code still needs Windows-compatible networking abstractions. Therefore, the current project is **macOS/Linux compatible, but not fully Windows compatible**.

The GoogleTest change itself should be made platform-conditional:

```cmake
if(APPLE OR UNIX)
    set_property(TARGET unit_tests APPEND PROPERTY
        BUILD_RPATH "$<TARGET_FILE_DIR:GTest::gtest_main>"
    )
endif()
```

Windows does not use ELF/Mach-O RPATH. Its DLL search path must be handled through the executable directory or copied runtime DLLs.

---

## 2. Multithreading review

The overall design is reasonable:

```text
libpcap callback / producer
        ↓
per-worker SPSC queue
        ↓
worker thread
        ↓
TLS parsing and fingerprint calculation
```

The flow-hash worker assignment is also correct because packets from the same flow are routed to the same worker queue.

### What is working correctly

- Each worker has its own queue.
- Each queue has exactly one producer and one consumer.
- Queue memory ordering uses acquire/release correctly.
- TLS parser scratchpads are worker-local.
- OpenSSL fingerprint contexts use thread-local storage.
- Packet data is copied into `HandshakeJob` before the callback returns.
- Worker threads are joined before `run()` returns.
- Output is protected by `stdout_mutex`.
- Atomic statistics are appropriate.
- The accumulator itself remains producer-thread-only, which is correct.

### Important issues

#### 1. Signal handler is not fully safe

`main.cpp` calls:

```cpp
engine->stop();
```

The `stop()` implementation calls:

```cpp
pcap_breakloop(pcap_handle_);
```

Calling `pcap_breakloop()` directly from a POSIX signal handler is not guaranteed to be async-signal-safe. This can cause undefined behavior during Ctrl+C, especially under load.

A safer design is:

```text
signal handler
    ↓
only set atomic stop flag
    ↓
capture loop notices the flag
    ↓
normal thread calls pcap_breakloop()
```

#### 2. Live capture silently drops work when a queue is full

In `capture.cpp`, live capture immediately gives up when the worker queue is full:

```cpp
if (!pushed) {
    stats_.dropped_packets.fetch_add(1, ...);
}
```

This can lose complete TLS handshakes and produce incomplete fingerprint results. The statistic is also misleading: it counts dropped handshake jobs, not dropped packets.

Recommended improvements:

- Rename it to `dropped_handshakes`.
- Add a separate `queue_overflows` counter.
- Use bounded backpressure or a larger dynamically managed queue.
- For live capture, explicitly document that overload may cause fingerprint loss.

#### 3. Offline mode can busy-wait excessively

Offline mode spins until the worker queue accepts a job:

```cpp
while (!stop_requested_.load(...)) {
    _mm_pause();
    ...
}
```

This can consume an entire CPU core while workers are processing. A condition-variable-based queue would be more efficient and would allow clean wake-up during shutdown.

#### 4. Database thread safety is implicit rather than explicit

`FingerprintDatabase` contains mutable state:

```cpp
std::unordered_map<std::string, FingerprintRecord> cache_;
std::unordered_set<std::string> missing_cache_;
int socket_;
```

The database methods themselves are not thread-safe.

At present, most calls happen while `stdout_mutex` is held, so the current implementation is accidentally serialized. However, this is fragile. Any future database lookup outside that output lock could create:

- concurrent `unordered_map` access,
- concurrent Redis socket access,
- corrupted replies,
- data races.

A dedicated `db_mutex` or a thread-safe database abstraction should be added.

#### 5. Output locking covers expensive operations

Workers hold `stdout_mutex` while performing:

- database lookups,
- Redis requests,
- interactive input,
- fingerprint reporting,
- console output.

This means one worker can block all other workers while Redis or terminal input is slow. The lock should ideally protect only final output formatting/writing. Database work should happen before acquiring the output mutex.

#### 6. Worker count can be excessive

The default is:

```cpp
std::thread::hardware_concurrency()
```

For a machine with many CPU cores, this creates one queue and one thread per core even when the capture contains little traffic. A practical cap such as 8, 16, or a configurable maximum would reduce overhead.

#### 7. Queue capacity is effectively 2047, not 2048

Because one slot is reserved to distinguish full from empty:

```cpp
const size_t next = (head + 1) % Capacity;
if (next == tail_) return false;
```

The usable capacity is `Capacity - 1`. This is correct behavior, but should be documented or represented with a named usable-capacity constant.

#### 8. `run()` is effectively single-use

After stopping, `stop_requested_` remains true. Calling `run()` again on the same `CaptureEngine` can result in different queue behavior and stale worker state. Either:

- explicitly prohibit repeated `run()` calls, or
- reset the state and recreate workers safely.

### Overall conclusion

The core producer/worker synchronization is sound. I did not find an obvious SPSC queue race or packet-lifetime bug.

The most important improvements are:

1. Fix signal-handler shutdown.
2. Make queue overflow behavior explicit and measurable.
3. Replace offline busy-waiting with condition variables.
4. Add explicit database synchronization.
5. Reduce the scope of `stdout_mutex`.
6. Add Windows networking portability before claiming full three-platform support.

The current implementation is suitable for macOS/Linux testing, but I would **not yet certify it as Windows-compatible or production-safe under sustained live-capture overload**.

User: Implement these 1. Fix signal-handler shutdown.
2. Make queue overflow behavior explicit and measurable.
3. Replace offline busy-waiting with condition variables.
4. Add explicit database synchronization.
5. Reduce the scope of `stdout_mutex`. Now do not worry about windows compatibity they are using wsl for that. I will then asking you for what are the other things that can be done for efficiency of the system to incease the throughput for the stress_test.pcap keeping that as standard we were previously getting higher aroung 0.75 million packets per second to not 0.5 million per second

Copilot: I’ll implement these as a coordinated capture-lifecycle change: signal handling will only request shutdown, capture will poll in bounded `pcap_dispatch` batches, workers will use condition variables for both work and offline backpressure, queue overflows will have dedicated counters, and database access will be mutex-protected.

Edit , , 
Completed with input: "*** Begin Patch\n*** Update File: /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/include/tlsfp/capture.hpp\n@@\n struct CaptureStats {\n     std::atomic<uint64_t> total_packets{0};\n     std::atomic<uint64_t> client_hellos{0};\n     std::atomic<uint64_t> server_hellos{0};\n-    std::atomic<uint64_t> dropped_packets{0};\n+    std::atomic<uint64_t> dropped_handshakes{0};\n+    std::atomic<uint64_t> queue_overflows{0};\n*** Update File: /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/main.cpp\n@@\n namespace {\n \n std::atomic`tlsfp::CaptureEngine*` g_engine{nullptr};\n \n void signal_handler(int sig) {\n     auto *engine = g_engine.load(std::memory_order_relaxed);\n     if (engine) {\n         engine->stop();\n     }\n-    // Restore default handler so a second interrupt immediately terminates\n-    std::signal(sig, SIG_DFL);\n }\n*** Update File: /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp\n@@\n #include <atomic>\n+#include <condition_variable>\n #include <mutex>\n@@\n struct WorkerContext {\n     SPSCQueue<HandshakeJob, 2048> queue;\n     ClientHelloData client_scratchpad;\n     ServerHelloData server_scratchpad;\n+    std::mutex queue_mutex;\n+    std::condition_variable queue_cv;\n     std::thread thread;\n };\n@@\n     std::atomic<bool> running{false};\n     std::mutex stdout_mutex;\n+    std::mutex db_mutex;\n     std::mutex enroll_mutex;\n@@\n     bool lookup(FingerprintKind kind, const std::string &hash, FingerprintRecord &record) {\n-        return db && db->lookup(kind, hash, record);\n+        std::lock_guard`std::mutex` lock(db_mutex);\n+        return db && db->lookup(kind, hash, record);\n@@\n-        if (db->lookup(kind, hash, record)) {\n+        if (lookup(kind, hash, record)) {\n             if (record.name.empty()) return \"<unnamed>\";\n             if (record.category.empty()) return record.name;\n             return record.name + \" (\" + record.category + \")\";\n@@\n         if (prompt_unknown) {\n             std::lock_guard`std::mutex` enroll_lock(enroll_mutex);\n-            if (db->lookup(kind, hash, record)) {\n+            if (lookup(kind, hash, record)) {\n                 if (record.name.empty()) return \"<unnamed>\";\n                 if (record.category.empty()) return record.name;\n                 return record.name + \" (\" + record.category + \")\";\n             }\n             std::cout << Color::YELLOW << \"\\n[?] Unknown \" << kind_name(kind) << \" fingerprint \"\n                       << hash << \". Enter verified client/server name (empty to skip): \" << std::flush;\n             std::string name;\n             if (std::getline(std::cin, name) && !name.empty()) {\n-                if (db->enroll(kind, hash, name)) {\n+                std::lock_guard`std::mutex` db_lock(db_mutex);\n+                if (db && db->enroll(kind, hash, name)) {\n                     return name + \" (enrolled)\";\n                 }\n             }\n@@\n-    bool pushed = worker.queue.emplace(init_job);\n+    bool pushed = false;\n+    {\n+        std::unique_lock`std::mutex` queue_lock(worker.queue_mutex);\n+        pushed = worker.queue.emplace(init_job);\n+        if (pushed) {\n+            queue_lock.unlock();\n+            worker.queue_cv.notify_one();\n+        }\n+    }\n \n     if (!pushed) {\n         if (!options_.read_filename.empty()) {\n-            while (!stop_requested_.load(std::memory_order_relaxed)) {\n-                #if defined(__x86_64__) || defined(_M_X64)\n-                _mm_pause();\n-                #else\n-                std::this_thread::yield();\n-                #endif\n-                if (worker.queue.emplace(init_job)) {\n-                    pushed = true;\n-                    break;\n-                }\n+            std::unique_lock`std::mutex` queue_lock(worker.queue_mutex);\n+            while (!stop_requested_.load(std::memory_order_acquire) &&\n+                   !worker.queue.emplace(init_job)) {\n+                worker.queue_cv.wait(queue_lock);\n+            }\n+            pushed = !stop_requested_.load(std::memory_order_acquire);\n+            if (pushed) {\n+                queue_lock.unlock();\n+                worker.queue_cv.notify_one();\n             }\n         }\n         if (!pushed) {\n-            stats_.dropped_packets.fetch_add(1, std::memory_order_relaxed);\n+            stats_.queue_overflows.fetch_add(1, std::memory_order_relaxed);\n+            stats_.dropped_handshakes.fetch_add(1, std::memory_order_relaxed);\n         }\n     }\n@@\n     for (auto &ctx : impl_->workers) {\n         WorkerContext *ctx_ptr = ctx.get();\n         ctx->thread = std::thread([this, ctx_ptr] {\n-            while (impl_->running.load(std::memory_order_acquire) || !ctx_ptr->queue.empty()) {\n-                bool processed = ctx_ptr->queue.pop_into([this, ctx_ptr](const HandshakeJob &job) {\n+            while (true) {\n+                std::unique_lock`std::mutex` queue_lock(ctx_ptr->queue_mutex);\n+                ctx_ptr->queue_cv.wait(queue_lock, [this, ctx_ptr] {\n+                    return !ctx_ptr->queue.empty() ||\n+                           !impl_->running.load(std::memory_order_acquire);\n+                });\n+\n+                if (ctx_ptr->queue.empty() &&\n+                    !impl_->running.load(std::memory_order_acquire)) {\n+                    break;\n+                }\n+\n+                bool processed = ctx_ptr->queue.pop_into([this, ctx_ptr](const HandshakeJob &job) {\n                     process_assembled_handshake(*ctx_ptr, job);\n                 });\n-                if (!processed) {\n-                    for (int spin = 0; spin < 32; ++spin) {\n-                        #if defined(__x86_64__) || defined(_M_X64)\n-                        _mm_pause();\n-                        #endif\n-                    }\n-                    if (!ctx_ptr->queue.empty()) continue;\n-                    std::this_thread::yield();\n+                queue_lock.unlock();\n+                if (processed) {\n+                    ctx_ptr->queue_cv.notify_one();\n                 }\n             }\n         });\n@@\n void CaptureEngine::stop() noexcept {\n     stop_requested_.store(true, std::memory_order_release);\n-    if (impl_) impl_->running.store(false, std::memory_order_release);\n-    if (pcap_handle_) pcap_breakloop(pcap_handle_);\n+    if (impl_) {\n+        impl_->running.store(false, std::memory_order_release);\n+        for (auto &worker : impl_->workers) {\n+            worker->queue_cv.notify_all();\n+        }\n+    }\n }\n@@\n-    int ret = pcap_loop(pcap_handle_, 0, global_pcap_callback, reinterpret_cast<u_char*>(this));\n+    int ret = 0;\n+    while (!stop_requested_.load(std::memory_order_acquire)) {\n+        ret = pcap_dispatch(pcap_handle_, 64, global_pcap_callback,\n+                            reinterpret_cast<u_char*>(this));\n+        if (ret < 0) break;\n+        if (ret == 0 && !options_.interface_name.empty()) continue;\n+        if (ret == 0) break;\n+    }\n \n     impl_->running.store(false, std::memory_order_release);\n     for (auto &worker : impl_->workers) {\n+        worker->queue_cv.notify_all();\n+    }\n+    for (auto &worker : impl_->workers) {\n         if (worker->thread.joinable()) worker->thread.join();\n     }\n@@\n-    if (ret < 0 && ret != -2) { // -2 is expected break from pcap_breakloop\n+    if (ret < 0) {\n*** End Patch\n"
Tool execution failed: Error: Failed to find expected lines in /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp:
        if (prompt_unknown) {
            std::lock_guard`std::mutex` enroll_lock(enroll_mutex);
            if (db->lookup(kind, hash, record)) {
                if (record.name.empty()) return "<unnamed>";
                if (record.category.empty()) return record.name;
                return record.name + " (" + record.category + ")";
            }
            std::cout << Color::YELLOW << "\n[?] Unknown " << kind_name(kind) << " fingerprint "
                      << hash << ". Enter verified client/server name (empty to skip): " << std::flush;
            std::string name;
            if (std::getline(std::cin, name) && !name.empty()) {
                if (db->enroll(kind, hash, name)) {
                    return name + " (enrolled)";
                }
            }

The header and signal-handler portions applied; the capture implementation patch hit a context mismatch because the enrollment code differs slightly from the expected text. I’ll inspect the exact remaining sections and apply the implementation in smaller, verifiable hunks.

Read , lines 1 to 35
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    1,
    35
  ]
}

Read , lines 245 to 445
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    245,
    445
  ]
}

Read , lines 455 to 650
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    455,
    650
  ]
}

Search for `dropped_packets|db->lookup|db->enroll|std::lock_guard<std::mutex> lock\(impl_...`

Edit 

Edit 

Edit 

Read , lines 830 to 925
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    830,
    925
  ]
}

Search for `dropped_packets|dropped_handshakes|queue_overflows|pcap_loop|pcap_breakloop|p...`

Read , lines 925 to 970
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    925,
    970
  ]
}

Edit , 
Completed with input: "*** Begin Patch\n*** Update File: /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp\n@@\n             }\n             uint16_t src_p = ntohs(key.src_port);\n             uint16_t dst_p = ntohs(key.dst_port);\n \n-            std::lock_guard`std::mutex` lock(impl_->stdout_mutex);\n             std::string label_ja3 = impl_->resolve_label(FingerprintKind::JA3, ja3.md5_hash, options_.prompt_unknown);\n             std::string label_ja4 = impl_->resolve_label(FingerprintKind::JA4, ja4.full_fp, options_.prompt_unknown);\n \n+            std::lock_guard`std::mutex` lock(impl_->stdout_mutex);\n             std::cout << \"\\n\" << Color::CLIENT_BADGE << \" \"\n@@\n             }\n             uint16_t src_p = ntohs(key.src_port);\n             uint16_t dst_p = ntohs(key.dst_port);\n \n-            std::lock_guard`std::mutex` lock(impl_->stdout_mutex);\n             std::string label_ja3s = impl_->resolve_label(FingerprintKind::JA3S, ja3s.md5_hash, options_.prompt_unknown);\n             std::string label_ja4s = impl_->resolve_label(FingerprintKind::JA4S, ja4s.full_fp, options_.prompt_unknown);\n \n+            std::lock_guard`std::mutex` lock(impl_->stdout_mutex);\n             std::cout << \"\\n\" << Color::SERVER_BADGE << \" \"\n*** Update File: /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp\n@@\n-        std::cerr << Color::RED << \"[!] pcap_loop error: \" << pcap_geterr(pcap_handle_) << Color::RESET << \"\\n\";\n+        std::cerr << Color::RED << \"[!] pcap_dispatch error: \" << pcap_geterr(pcap_handle_) << Color::RESET << \"\\n\";\n*** Update File: /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/main.cpp\n@@\n         std::cout << \"Total Packets:    \" << stats.total_packets.load() << \"\\n\"\n                   << \"ClientHellos:     \" << stats.client_hellos.load() << \"\\n\"\n                   << \"ServerHellos:     \" << stats.server_hellos.load() << \"\\n\";\n+        std::cout << \"Dropped Handshakes: \" << stats.dropped_handshakes.load() << \"\\n\"\n+                  << \"Queue Overflows:    \" << stats.queue_overflows.load() << \"\\n\";\n@@\n                   << \"Total Packets Scanned : \" << stats.total_packets.load() << \"\\n\"\n                   << \"ClientHellos Found    : \" << stats.client_hellos.load() << \"\\n\"\n                   << \"ServerHellos Found    : \" << stats.server_hellos.load() << \"\\n\"\n+                  << \"Dropped Handshakes    : \" << stats.dropped_handshakes.load() << \"\\n\"\n+                  << \"Queue Overflows       : \" << stats.queue_overflows.load() << \"\\n\"\n*** End Patch\n"
Tool execution failed: Error: Failed to find expected lines in /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/main.cpp:
        std::cout << "Total Packets:    " << stats.total_packets.load() << "\n"
                  << "ClientHellos:     " << stats.client_hellos.load() << "\n"
                  << "ServerHellos:     " << stats.server_hellos.load() << "\n";

Read , lines 105 to 150
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/main.cpp",
  "view_range": [
    105,
    150
  ]
}

Read , lines 645 to 695
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    645,
    695
  ]
}

Read , lines 198 to 235
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    198,
    235
  ]
}

Edit , 

The implementation is now complete, including bounded condition-variable waits so a signal can stop a producer or worker without invoking non-signal-safe condition-variable operations from the signal handler. I’ll build and run the full CTest suite, then inspect the diff for stale counters or shutdown regressions.

Search for `dropped_packets|pcap_loop|pcap_breakloop|db->lookup|db->enroll`

Ran terminal command: cd 'Phase 2/engine' && cmake -S . -B build && cmake --build build --parallel

Read , lines 470 to 700
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    470,
    700
  ]
}

Ran terminal command: git --no-pager diff --check && git --no-pager diff --stat && git --no-pager status --short

Ran terminal command: cd 'Phase 2/engine' && ctest --test-dir build --output-on-failure

Edit 
Completed with input: "*** Begin Patch\n*** Update File: /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp\n@@\n-    if (ret < 0) {\n+    if (ret < 0 && !stop_requested_.load(std::memory_order_acquire)) {\n         std::cerr << Color::RED << \"[!] pcap_dispatch error: \"\n                   << pcap_geterr(pcap_handle_) << Color::RESET << \"\\n\";\n         return false;\n*** End Patch\n"
Tool execution failed: Failed to apply patch: Error: Failed to find expected lines in /Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp:
    if (ret < 0) {
        std::cerr << Color::RED << "[!] pcap_dispatch error: "
                  << pcap_geterr(pcap_handle_) << Color::RESET << "\n";
        return false;

Read , lines 675 to 692
Completed with input: {
  "path": "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting/Phase 2/engine/src/capture.cpp",
  "view_range": [
    675,
    692
  ]
}

Edit 

All 46 tests pass after the threading changes. I also corrected shutdown handling so an interrupted `pcap_dispatch` is treated as a normal stop rather than reported as a capture error; I’ll perform one final build/diff validation now.

Ran terminal command: git --no-pager diff --check && git --no-pager diff -- 'Phase 2/engine/include/tlsfp/capture.hpp' 'Phase 2/engine/src/main.cpp' 'Phase 2/engine/src/capture.cpp' | sed -n '1,260p'

Ran terminal command: cd 'Phase 2/engine' && cmake --build build --parallel && ctest --test-dir build --output-on-failure

One final edge case appeared in the offline retry path: a stop signal could arrive immediately after a successful enqueue and falsely count that job as dropped. I’m correcting that accounting race before finishing.

Edit 

Ran terminal command: cd 'Phase 2/engine' && cmake --build build --parallel >/dev/null && ctest --test-dir build --output-on-failure >/dev/null && git --no-pager diff --check && echo 'build and 46 tests passed'

Implemented all five requested changes.

### Changes

- **Signal shutdown:** signal handler now only sets atomic stop state; no `pcap_breakloop()` or condition-variable calls from the signal handler.
- **Queue overflow metrics:**
  - Added `dropped_handshakes`
  - Added `queue_overflows`
  - Added both to normal and benchmark summaries.
- **Condition variables:** replaced offline busy-spinning with per-worker condition-variable waiting.
- **Database synchronization:** added a database mutex protecting cache and Redis socket access.
- **Reduced output lock scope:** fingerprint database lookups now occur before acquiring `stdout_mutex`.
- **Capture loop:** switched from `pcap_loop()` to bounded `pcap_dispatch()` batches so shutdown is responsive.

Modified:

- `capture.hpp`
- `capture.cpp`
- `main.cpp`

Validation completed:

```text
Build successful
46/46 tests passed
git diff --check passed
```

The stress-test throughput was not benchmarked yet, so the next step can measure whether the condition-variable and synchronization changes improved or reduced performance against `stress_test.pcap`.