# Session 1 — Project Planning, Roles, and Technical Direction

## Project

CS331-T014 — TLS Fingerprinting.

The team planned two implementations: Python and C++. The project centered on extracting TLS ClientHello/ServerHello data and computing JA3/JA3S, with JA4/JA4S later implemented as well.

## Roles discussed

- Satyakam — C++ implementation
- Pranjal — Python implementation
- Harshal — fingerprint database / Redis-side work
- Divyansh — GUI work
- Manognya — testing, benchmarking, stress testing, showcase planning, and integration support
- Ujas — coordination / C++ / overall integration discussions

## Verbatim user prompt

> what is pcap?

### Response head

A PCAP was explained as a packet-capture file: a recorded sequence of packets from a network interface. It became the common offline input used to compare Python, C++, and TShark.

---

## Reconstructed context

The user asked what their contribution should be after the team meeting and wanted work that could be independently demonstrated.

### Response

The work was broken into:

1. correctness validation,
2. benchmark Python,
3. benchmark C++,
4. compare Python vs C++,
5. investigate whether Python's library stack was a bottleneck,
6. stress-test live capture,
7. help plan the final showcase.

The discussion also separated **offline performance benchmarking** from **live stress testing**, because they answer different questions.

---

## Verbatim user prompt

> I wanted to get started with GUI

### Response head

The GUI could start once the engine output format was sufficiently stable. Two practical directions were discussed: Streamlit for a fast dashboard and PySide6 for a more native Wireshark-like application.

---

## Verbatim user prompt

> what is better per requirements

### Response head

PySide6 was considered the stronger fit for a native packet-analysis tool, while Streamlit was the faster option for a lightweight demo.

---

## Reconstructed context — testing/showcase plan

A practical course-project testing strategy was established:

- correctness with known PCAPs,
- cross-checking with Wireshark/TShark,
- real client captures,
- repeatable replay using `tcpreplay`,
- higher-rate stress if useful,
- final demonstration with multiple distinct clients,
- explicit limitations and unknown fingerprints.

## Main outcome

The user's main ownership area became **testing + benchmarking + stress testing + showcase readiness**.
