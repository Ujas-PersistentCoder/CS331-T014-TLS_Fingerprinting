# Final sprint plan and GUI analysis

**Created:** 9/7/2026 15:27:16  
**Updated:** 9/7/2026 15:31:27  
**Exported:** 9/13/2026 15:00:50  
**Link:** [https://claude.ai/chat/490b0ce5-191f-49ed-8548-96b55888ba13](https://claude.ai/chat/490b0ce5-191f-49ed-8548-96b55888ba13)  

## User:

> 9/7/2026 15:27:18

Our current plan for the final sprint of project:

1. Work on GUI for Python, we already have a working prototype but it does require improvements and bug fixes.
2. We stick with the CLI for C++, no GUI.
3. Perform benchmarking, report metrics and detailed comparison for both the C++ and Python engines
4. Write the report based on the results
5. Prepare the PPT for the demo, and rehearse the demo with the evaluator. Specially curated pcap for the demo.

Starting with the GUI: analyse the latest implementation of the PyQt6 GUI and find limitations / edge cases / poor UX

## Assistant:

> 9/7/2026 15:31:27

> Structuring findings into a severity-ranked review response.
>
> - Structuring findings into a severity-ranked review response.
> - **Done**

I went through `window.py`, `workers.py`, and `main.py` line by line. There are three data-corruption bugs, several crash/freeze risks, and a handful of real UX gaps. Ranked by how much they should worry you before the demo:

## Bugs that corrupt your data (fix these first — this is your actual deliverable)

**1. `labelSelectedFingerprint` mislabels JA4S hashes as client fingerprints.**
`fingerprintKind` for a server row is set to `"ja3s"` if JA3S was unknown, or `"ja4s"` if JA3S was already known but JA4S wasn't. The pair-selection check only tests `== "ja3s"`:
```python
if entry.get("fingerprintKind") == "ja3s":
    pair = (("ja3s", ...), ("ja4s", ...))
# else falls through to the client pair: ("ja3", ...), ("ja4", ...)
```
So whenever a ServerHello row has a known JA3S but unknown JA4S (`fingerprintKind == "ja4s"`), it falls into the client branch and calls `enroll(entry["ja4Hash"], "ja4", label)` — enrolling a JA4S string (`t130200_...`) under the `ja4` (client) kind. This is the exact same class of bug you already found and fixed in `db.py` ("Reference DB contamination"), except it's unfixed here in the GUI's own labeling path. Fix: check `fingerprintKind in ("ja3s", "ja4s")`, or better, store an explicit `role` field instead of overloading `fingerprintKind`.

**2. `server_packet_data()` never computes the raw JA3S string.**
```python
"ja3Raw": "N/A",
```
`compute_ja3s_string` is imported and unused for this path. Every ServerHello detail view is permanently missing its raw string — trivial one-line fix.

**3. `captureFinished` signal is defined, emitted, and never connected.**
`PcapWorker.captureFinished = pyqtSignal(str)` fires `self.captureStats.summary()` at the end of a run, but `window.py` never does `.connect()` on it. Consequence: if you load a pcap with zero TLS traffic (wrong port, no handshake, malformed file that silently no-ops), you get an empty table and no error and no completion signal — no way to tell "still working" from "found nothing" from "silently broke." Wire this into the details pane or a status bar.

## Freeze / crash risks

**4. `FingerprintDB()` construction blocks the GUI thread, not the worker thread.**
`PcapWorker.__init__` and `LiveCaptureWorker.__init__` both construct `FingerprintDB`, and `FingerprintDB.__init__` does a Redis `connect()` + `client.ping()` + full reseed of `seed_fingerprints.json`/`capture_manifest.json`/legacy `fingerprints.json` if the connection succeeds. These workers are constructed in `selectPcapFile()`/`toggleLiveCapture()` on the **main thread**, before `.start()` is even called. Every single "Load PCAP" click and every "Start Live Capture" click re-runs a full Redis reconnect + reseed synchronously on the UI thread. Same thing happens once more, unconditionally, in `TlsMonitorGui.__init__` for the window's own DB instance — so opening the app at all pays this cost before the window renders. No connect timeout is set either, so if Redis is unreachable (not just off), this can hang for a long time, not just a network round-trip.

**5. No guard against overlapping workers.**
`selectPcapFile()` reassigns `self.pcapWorker = PcapWorker(...)` with no check on whether a previous one is still running, and no parent is set on the QThread — if the old instance's only Python reference disappears while its thread is still executing, you're relying on luck, not ownership, to keep it alive. Nothing stops the user from clicking "Start Live Capture" while a big pcap is still loading either — `toggleLiveCapture` clears the table and starts a second reassembler while `PcapWorker` may still be emitting rows into that same table.

**6. No `closeEvent` override.**
Close the window while a `PcapWorker` or, worse, a `LiveCaptureWorker` (holding a live scapy sniffer thread) is running, and nothing stops or joins it. Best case: Qt warns about a QThread destroyed while running. Worst case on some platforms: it doesn't warn, it just crashes or leaves an orphaned sniffing thread.

**7. `stopCapture()` calls `self.wait()` on the GUI thread.**
Bounded by the 100ms poll loop in normal operation, but if `self.sniffer.stop()` inside `run()` ever blocks (interface issue, permissions changing mid-capture), your UI freezes with no way to cancel — because you're calling a blocking wait from the thread that owns the button the user is trying to click again.

## UX gaps

**8. Live capture BPF filter is hardcoded to `"tcp port 443"`, with no UI control.** The CLI takes `-f <bpf_filter>`; the GUI doesn't expose this at all. If you test against your own `openssl s_server` on a non-standard local port (which the manifest suggests you do), the GUI live capture will show nothing and you won't know why until you've wasted demo time debugging it.

**9. The table doesn't distinguish ClientHello rows from ServerHello rows.** Same generic "JA3 Hash / JA4 Hash / JA3 Match / JA4 Match" columns are reused for both (server rows just show "N/A" for SNI). For a project whose entire point is client-vs-server fingerprint distinction, this is a bad look in front of an evaluator. Add a Role/Type column.

**10. All the reassembly diagnostics the CLI reports (`CaptureStats.summary()` — segments reordered, retransmissions dropped, gaps unresolved, HRR-relevant flow counts) are computed but never surfaced in the GUI at all**, not even via the orphaned `captureFinished` signal. That's the evidence you're planning to put in the report; right now it only exists in the CLI output.

**11. No cancel button for pcap replay**, no autoscroll on the table during live capture, `Stretch` resize mode on all 7 columns (hash columns and the SNI/Match columns fight for the same width regardless of actual content length), and the interface dropdown is populated once at startup with no refresh.

**12. Minor packaging smell:** `PyQt6` sits in `code/python/requirements.txt`, the core engine's dependency file, even though it's only needed by `code/gui`. Not a functional bug, but worth splitting before you hand off the repo.

That's the full list. #1–3 are the ones that actually threaten correctness of your deliverable; #4 is the one most likely to make the GUI look broken/slow in front of the evaluator; #8 is the one most likely to bite you specifically during the demo if your test server isn't on port 443.

Which do you want me to fix first?

Powered by Claude Exporter (https://www.ai-chat-exporter.net)
