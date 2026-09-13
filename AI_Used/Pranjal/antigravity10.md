[README.md](file;file:///Users/pranjal/Projects/CS%20331%20CN%202026/TLS-Fingerprinting/README.md) the install instructions are for linux. Can you tell me the commands to set everything up for macOS? Don't update teh README yet

Viewed README.md:1-112
Listed directory CS%20331%20CN%202026
Listed directory TLS-Fingerprinting
Viewed CMakeLists.txt:1-168
Ran command: `which brew cmake redis-server redis-cli openssl clang++`
Ran command: `brew list --formula | grep -E "openssl|pcap|redis"`
Ran command: `cd TLS-Fingerprinting && cmake -S code/cpp -B build_test -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)`
Used tool: manage_task
Ran command: `rm -rf build_test`

Here are the equivalent commands and instructions to set up and run everything on **macOS** (without modifying [README.md](file:///Users/pranjal/Projects/CS%20331%20CN%202026/TLS-Fingerprinting/README.md)):

---

### 1. Install System Dependencies

macOS uses [Homebrew](https://brew.sh) instead of `apt`, and Xcode Command Line Tools instead of `build-essential`. macOS already includes `libpcap` headers in its SDK and `venv` in Python.

```bash
# 1. Install Xcode Command Line Tools (compiler & toolchain, if not already installed)
xcode-select --install

# 2. Install CMake, OpenSSL 3, and Redis via Homebrew
brew install cmake openssl@3 redis
```

---

### 2. Redis Database Setup

macOS does not use `systemctl`. You can manage Redis as a background daemon using `brew services`:

```bash
# Start Redis in the background (starts now and on login)
brew services start redis

# Verify Redis is running
redis-cli ping
# Expected output: PONG
```

*(Optional note: To stop Redis later, run `brew services stop redis`, or run it in the foreground with `redis-server`).*

---

### 3. Build the C++ Engine

On macOS, OpenSSL is installed in Homebrew's keg (`/opt/homebrew/opt/openssl@3` on Apple Silicon). Point CMake to the OpenSSL prefix using `brew --prefix`:

From the `TLS-Fingerprinting` repository directory:

```bash
cd "/Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting"

# Configure with OpenSSL hint
cmake -S code/cpp -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)

# Compile with all CPU cores
cmake --build build --parallel
```

#### Running the Engine:
- **Offline PCAP analysis:**
  ```bash
  ./build/tlsfp_engine -r code/pcaps/test_ja3.pcap
  ```
- **Live Capture (macOS interface differences):**
  On macOS, loopback is **`lo0`** (not `lo`), and primary Wi-Fi is usually **`en0`**:
  ```bash
  # Loopback
  sudo ./build/tlsfp_engine -i lo0 -f "tcp port 443"

  # Or Wi-Fi / physical interface
  sudo ./build/tlsfp_engine -i en0 -f "tcp port 443"
  ```

---

### 4. Python Environment & Dependencies

You already have `.venv` set up at the project root (`/Users/pranjal/Projects/CS 331 CN 2026/.venv`) and the requirements installed. 

Whenever you open a new shell:

```bash
cd "/Users/pranjal/Projects/CS 331 CN 2026"
source .venv/bin/activate

# (If needed in the future to re-install requirements)
pip install -r TLS-Fingerprinting/code/python/requirements.txt
```

---

### 5. Run the Python GUI & Tests

From within `TLS-Fingerprinting` (with the virtual environment active):

```bash
cd "/Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting"
source ../.venv/bin/activate

# Launch GUI (PyQt6 runs natively on macOS)
python code/gui/main.py

# Run unit tests
python -m pytest code/python/tests -q
```

---

### Summary of Key macOS Differences vs Linux

| Linux (Ubuntu / WSL) | macOS |
| :--- | :--- |
| `apt install build-essential` | `xcode-select --install` |
| `apt install libssl-dev` | `brew install openssl@3` |
| `apt install redis-server` | `brew install redis` |
| `sudo systemctl start redis-server` | `brew services start redis` |
| `cmake -S code/cpp -B build` | `cmake -S code/cpp -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)` |
| Loopback interface: `lo` | Loopback interface: `lo0` (Wi-Fi is `en0`) |

Ran command: `brew services start redis
`
Ran command: `redis-cli ping`
Ran command: `cd TLS-Fingerprinting`
Ran command: `cmake -S code/cpp -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)`
Ran command: `cmake --build build --parallel`

---

TLS-Fingerprinting  main[$] 
❯ cmake -S code/cpp -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
-- The CXX compiler identification is AppleClang 21.0.0.21000101
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Found OpenSSL: /opt/homebrew/opt/openssl@3/lib/libcrypto.dylib (found version "3.6.4")
-- Performing Test CMAKE_HAVE_LIBC_PTHREAD
-- Performing Test CMAKE_HAVE_LIBC_PTHREAD - Success
-- Found Threads: TRUE
CMake Warning (deprecated) at /Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/build/_deps/googletest-src/CMakeLists.txt:4 (cmake_minimum_required):
  Compatibility with CMake < 3.10 will be removed from a future version of
  CMake.

  Update the VERSION argument <min> value.  Or, use the <min>...<max> syntax
  to tell CMake that the project requires at least <min> but has been updated
  to work with policies introduced by <max> or earlier.
This warning is for project developers.  Use -Wno-author or -Wno-deprecated
to suppress it.

-- The C compiler identification is AppleClang 21.0.0.21000101
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
CMake Warning (deprecated) at /Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/build/_deps/googletest-src/googlemock/CMakeLists.txt:39 (cmake_minimum_required):
  Compatibility with CMake < 3.10 will be removed from a future version of
  CMake.

  Update the VERSION argument <min> value.  Or, use the <min>...<max> syntax
  to tell CMake that the project requires at least <min> but has been updated
  to work with policies introduced by <max> or earlier.
This warning is for project developers.  Use -Wno-author or -Wno-deprecated
to suppress it.

CMake Warning (deprecated) at /Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/build/_deps/googletest-src/googletest/CMakeLists.txt:49 (cmake_minimum_required):
  Compatibility with CMake < 3.10 will be removed from a future version of
  CMake.

  Update the VERSION argument <min> value.  Or, use the <min>...<max> syntax
  to tell CMake that the project requires at least <min> but has been updated
  to work with policies introduced by <max> or earlier.
This warning is for project developers.  Use -Wno-author or -Wno-deprecated
to suppress it.

-- Found Python: /opt/homebrew/Frameworks/Python.framework/Versions/3.14/bin/python3.14 (found version "3.14.7") found components: Interpreter
-- Configuring done (7.7s)
-- Generating done (0.1s)
-- Build files have been written to: /Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/build
TLS-Fingerprinting  main[$] took 8s 
❯ cmake --build build --parallel
[ 11%] Building CXX object CMakeFiles/tlsfp_lib.dir/src/parser.cpp.o
[ 11%] Building CXX object CMakeFiles/tlsfp_lib.dir/src/capture.cpp.o
[ 33%] Building CXX object CMakeFiles/tlsfp_lib.dir/src/ja4.cpp.o
[ 33%] Building CXX object CMakeFiles/tlsfp_lib.dir/src/db.cpp.o
[ 33%] Building CXX object CMakeFiles/tlsfp_lib.dir/src/ja3.cpp.o
[ 33%] Building CXX object _deps/googletest-build/googletest/CMakeFiles/gtest.dir/src/gtest-all.cc.o
/Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/code/cpp/src/parser.cpp:23:67: warning: 
      implicit conversion loses integer precision: 'int' to 'uint16_t'
      (aka 'unsigned short') [-Wimplicit-int-conversion]
   23 |         uint16_t val = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
      |                  ~~~   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~
/Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/code/cpp/src/parser.cpp:322:89: warning: 
      implicit conversion loses integer precision: 'int' to 'uint16_t'
      (aka 'unsigned short') [-Wimplicit-int-conversion]
  322 |   ...uint16_t ver = (static_cast<uint16_t>(reader.data[reader.offset]) << 8) |
      |               ~~~   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^
  323 |                                 reader.data[reader.offset + 1];
      |                                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
2 warnings generated.
/Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/code/cpp/src/capture.cpp:155:66: warning: 
      implicit conversion loses integer precision: 'int' to 'uint16_t'
      (aka 'unsigned short') [-Wimplicit-int-conversion]
  155 |             ethertype = (static_cast<uint16_t>(packet[12]) << 8) | packet[13];
      |                       ~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~
/Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/code/cpp/src/capture.cpp:160:87: warning: 
      implicit conversion loses integer precision: 'int' to 'uint16_t'
      (aka 'unsigned short') [-Wimplicit-int-conversion]
  160 |   ...ethertype = (static_cast<uint16_t>(packet[link_header_len + 2]) << 8) | 
      |                ~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^
  161 |                              packet[link_header_len + 3];
      |                              ~~~~~~~~~~~~~~~~~~~~~~~~~~~
/Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/code/cpp/src/capture.cpp:169:65: warning: 
      implicit conversion loses integer precision: 'int' to 'uint16_t'
      (aka 'unsigned short') [-Wimplicit-int-conversion]
  169 |             ethertype = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
      |                       ~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~
/Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/code/cpp/src/capture.cpp:175:66: warning: 
      implicit conversion loses integer precision: 'int' to 'uint16_t'
      (aka 'unsigned short') [-Wimplicit-int-conversion]
  175 |             ethertype = (static_cast<uint16_t>(packet[14]) << 8) | packet[15];
      |                       ~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~
/Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/code/cpp/src/capture.cpp:336:71: warning: 
      implicit conversion loses integer precision: 'int' to 'uint16_t'
      (aka 'unsigned short') [-Wimplicit-int-conversion]
  336 |     uint16_t tls_rec_len = (static_cast<uint16_t>(buf.bytes[3]) << 8) | buf.bytes[4];
      |              ~~~~~~~~~~~   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~
5 warnings generated.
[ 38%] Linking CXX static library libtlsfp_lib.a
[ 38%] Built target tlsfp_lib
[ 44%] Building CXX object CMakeFiles/tlsfp_engine.dir/src/main.cpp.o
[ 50%] Linking CXX executable tlsfp_engine
[ 50%] Built target tlsfp_engine
[ 55%] Linking CXX static library ../../../lib/libgtest.a
[ 55%] Built target gtest
[ 66%] Building CXX object _deps/googletest-build/googletest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o
[ 66%] Building CXX object _deps/googletest-build/googlemock/CMakeFiles/gmock.dir/src/gmock-all.cc.o
[ 72%] Linking CXX static library ../../../lib/libgtest_main.a
[ 72%] Built target gtest_main
[ 77%] Building CXX object CMakeFiles/tlsfp_unit_tests.dir/tests/test_fingerprints.cpp.o
[ 83%] Linking CXX static library ../../../lib/libgmock.a
[ 83%] Built target gmock
[ 88%] Building CXX object _deps/googletest-build/googlemock/CMakeFiles/gmock_main.dir/src/gmock_main.cc.o
[ 94%] Linking CXX static library ../../../lib/libgmock_main.a
[ 94%] Built target gmock_main
[100%] Linking CXX executable tlsfp_unit_tests
[100%] Built target tlsfp_unit_tests

The build succeeded completely! Both the main binary `tlsfp_engine` and unit tests `tlsfp_unit_tests` compiled and linked cleanly.

*(Note on the warnings: They are just `-Wimplicit-int-conversion` from `-Wconversion`—in C++, bitwise operations on `uint16_t` promote operands to `int` before storing back into `uint16_t`. They are completely harmless.)*

---

### Next Steps to Test

You are currently inside `TLS-Fingerprinting`. You can run any of the following to verify functionality:

1. **Run the C++ unit tests:**
   ```bash
   ./build/tlsfp_unit_tests
   ```
   *(or via CTest: `ctest --test-dir build --output-on-failure`)*

2. **Run the C++ engine on a sample PCAP:**
   ```bash
   ./build/tlsfp_engine -r code/pcaps/test_ja3.pcap
   ```

3. **Run the Python test suite:**
   ```bash
   source ../.venv/bin/activate
   python -m pytest code/python/tests -q
   ```

4. **Launch the Python GUI:**
   ```bash
   source ../.venv/bin/activate
   python code/gui/main.py
   ```