Look for geniune limitations of our project
Viewed README.md:1-112
Listed directory TLS-Fingerprinting
Listed directory code
Searched for "TODO|FIXME|NOTE|Limitation"
Searched for "TODO|FIXME"
Searched for "QUIC|UDP|IPv6|limitation"
Viewed capture.py:1-50
Searched for "limit|Limit"
Viewed capture.hpp:1-109
Created project_limitations.md

I've thoroughly reviewed the codebase, project architecture, and your `AGENTS.md` rules to identify the genuine technical and structural limitations of the TLSFP Engine. 

I've documented my findings in a structured report artifact:
[project_limitations.md](file:///Users/pranjal/.gemini/antigravity-ide/brain/55195f07-de42-49d1-900a-77aa1ed8b6a5/project_limitations.md)

Here is a brief summary of the most critical limitations:

1. **Strictly TCP Bound (No QUIC):** The engine completely ignores UDP traffic, meaning it cannot fingerprint HTTP/3 (QUIC) connections.
2. **TCP Reassembly Edge Cases:** The custom stream reassembler drops state during sequence number wraparound, ignores window scaling, has hard-capped out-of-order buffers (`MAX_OOO_SEGMENTS = 10` in Python, `4096` bytes in C++), and may lose bytes during TCP Fast Open (TFO).
3. **Evasion through Instability:** As intentionally documented, modern browser features like GREASE (RFC 8701) and ClientHello extension permutations severely limit the deterministic stability of the resulting fingerprints.
4. **Implementation Restrictions:** Following your `AGENTS.md` guidelines, JA4/JA4S implementation remains incomplete/paused pending full validation of the JA3/JA3S implementation against `ja3er.com`.
5. **Passive Visibility Only:** Because it does not decrypt payloads, the engine is blind to post-handshake TLS behavior (like TLS 1.3 Encrypted Extensions) and is vulnerable to TLS-terminating middleboxes masking the true client fingerprint.

Let me know if you'd like to dive deeper into any of these areas or explore potential workarounds!