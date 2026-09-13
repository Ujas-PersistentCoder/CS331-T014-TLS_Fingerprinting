Test code/pcaps/python_requests.pcap on the python engine and C++ engine and report the results from both

Listed directory code
Listed directory python
Listed directory cpp
Viewed main.py:1-149
Listed directory build
Listed directory TLS-Fingerprinting
Listed directory CS%20331%20CN%202026
Listed directory build
Ran command: `source "/Users/pranjal/Projects/CS 331 CN 2026/.venv/bin/activate" && python code/python/main.py pcap code/pcaps/python_requests.pcap`
Ran command: `./build/tlsfp_engine --help`
Ran command: `./build/tlsfp_engine -r code/pcaps/python_requests.pcap`

I've tested the `python_requests.pcap` file using both the Python and C++ engines. Here are the results:

### **Python Engine Results**
Executed using the `.venv` virtual environment:

```text
Analyzing PCAP: code/pcaps/python_requests.pcap

[ClientHello] 10.7.13.156:51974 -> 104.16.124.96:443
  SNI:     www.cloudflare.com
  JA3:     a48c0d5f95b1ef98f560f324fd275da1
  JA3 raw: 771,4866-4867-4865-49196-49200-49195-49199-52393-52392-49188-49192-49187-49191-159-158-107-103-255,0-11-10-16-22-23-49-13-43-45-51-21,29-23-30-25-24-256-257-258-259-260,0-1-2
  Match:   Unknown
  JA4:     t13d1812h1_85036bcba153_b26ce05bbdd6

[ServerHello] 104.16.124.96:443 -> 10.7.13.156:51974
  JA3S:     907bf3ecef1c987c889946b737b43de8
  JA3S raw: 771,4866,51-43
  JA4S:    t130200_1302_a56c5b993250
  JA4S Match: OpenSSL s_server (from DB)
```

### **C++ Engine Results**
Executed using the built `tlsfp_engine`:

```text
[*] Reading from offline capture: code/pcaps/python_requests.pcap
[*] Capture initialized. Datalink type: 1
[*] Redis fingerprint database loaded: 64 entries
[+] Captured ClientHello | Flow: [10.7.13.156]:51974 -> [104.16.124.96]:443 | Reassembled Size: 517 bytes
  ├─ [SNI]        www.cloudflare.com
  ├─ [JA3 String] 771,4866-4867-4865-49196-49200-49195-49199-52393-52392-49188-49192-49187-49191-159-158-107-103-255,0-11-10-16-22-23-49-13-43-45-51-21,29-23-30-25-24-256-257-258-259-260,0-1-2
  ├─ [JA3 Hash]   a48c0d5f95b1ef98f560f324fd275da1
  ├─ [JA3 Match]  <unknown>
  ├─ [JA4]        t13d1812h1_85036bcba153_b26ce05bbdd6
  └─ [JA4 Match]  <unknown>
[+] Captured ServerHello | Flow: [104.16.124.96]:443 -> [10.7.13.156]:51974 | Reassembled Size: 127 bytes
  ├─ [JA3S String] 771,4866,51-43
  ├─ [JA3S Hash]   907bf3ecef1c987c889946b737b43de8
  ├─ [JA3S Match]  <unknown>
  ├─ [JA4S]        t130200_1302_a56c5b993250
  └─ [JA4S Match]  OpenSSL s_server (server)
[*] Reached end of capture file.
```

### **Summary of Results**
Both engines have achieved **exact parity** on this PCAP trace:
- **JA3:** Both output the exact same string and hash (`a48c0d5f95b1ef98f560f324fd275da1`).
- **JA4:** Both compute the exact same client fingerprint (`t13d1812h1_85036bcba153_b26ce05bbdd6`).
- **JA3S:** Both calculate the same hash (`907bf3ecef1c987c889946b737b43de8`).
- **JA4S:** Both return the same server fingerprint (`t130200_1302_a56c5b993250`).
- Both correctly identified the JA4S match `OpenSSL s_server` via their respective fingerprint lookup mechanisms (JSON file for Python and Redis for C++).

Viewed seed_fingerprints.json:251-265

---

Why unknown match for JA3 and JA4 for both the engines

Searched for "a48c0d5f95b1ef98f560f324fd275da1"
Searched for "requests"
Viewed seed_fingerprints.json:150-265

Both engines are returning an "Unknown" match because the exact JA3 and JA4 fingerprints generated from `python_requests.pcap` do not exist in your `seed_fingerprints.json` database.

When we look at the hashes produced from the PCAP versus what is in the database for `Python requests/urllib3`, we can see they are completely different:

### Produced from `python_requests.pcap`
*   **JA3 Hash:** `a48c0d5f95b1ef98f560f324fd275da1`
*   **JA4 Hash:** `t13d1812h1_85036bcba153_b26ce05bbdd6`

### Existing in `seed_fingerprints.json`
*   **JA3 Hash:** Not present
*   **JA4 Hash:** `t13d3112h1_e8f1e7e78f70_b26ce05bbdd6` (from `client_requests.pcap`)

### Why are they different?
Even though both are from "Python requests", the TLS fingerprint is highly dependent on the underlying environment making the request. In this case, there is a significant difference in the cipher suites being offered:

1.  **Cipher Suite Count:** The JA4 hash from the PCAP starts with `t13d1812h1`, meaning it offered **18 cipher suites**. The database entry starts with `t13d3112h1`, meaning it offered **31 cipher suites**.
2.  **Cipher Suite Hash:** The middle portion of the JA4 hash represents the sorted ciphers (`85036bcba153` in the PCAP vs `e8f1e7e78f70` in the DB), confirming that the ciphers themselves are completely different.

**Conclusion:** The machine/environment that captured `python_requests.pcap` was likely using a different version of OpenSSL (or Python/urllib3) than the environment that captured `client_requests.pcap` which seeded the database. This difference in the underlying TLS library causes a different `ClientHello` to be generated, resulting in an unrecognized fingerprint.

Viewed seed_fingerprints.json:234-249

---

Document this is a limitation of our system. How our current database was created only using a specific environment and version of the clients. On different devices / environment, the hashes are different, and hence don't match with DB. Also the observation made in the JA4 hash. 

Listed directory report
Searched for "limitation"
Viewed tls_fingerprinting_report.md:210-240
Edited tls_fingerprinting_report.md

I have successfully updated the `tls_fingerprinting_report.md` file to include this limitation. 

I've added it as point `(g)` under the `6.2 Limitations` section, explicitly explaining how environment-dependent fingerprint drift works, and using our observation about the JA4 cipher counts (`t13d31...` vs `t13d18...`) as a concrete example of why exact hash matching fails across different environments. 

Here is the section that was added:
> **(g) Environment-Dependent Fingerprint Drift**: TLS fingerprints are highly dependent on the underlying environment generating the request (e.g., OpenSSL library version linked against the client on a specific OS). An exact match against our curated database requires the exact same environment used to generate the seed capture. For example, a `Python requests` client running on one machine may offer 31 cipher suites, generating one JA3/JA4 hash, while the exact same Python script on a different machine with a different TLS backend may offer 18 cipher suites, resulting in completely different JA3 and JA4 hashes. This is explicitly visible in the JA4 signature format, where the cipher count (e.g., `t13d31...` vs `t13d18...`) and truncated sorted cipher hashes drastically diverge. Consequently, cross-environment testing frequently results in "Unknown" matches because exact hash lookups are extremely brittle to environment drift.