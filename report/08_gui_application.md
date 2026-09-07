# GUI Application — PyQt6 TLS Fingerprint Monitor

**Document Scope:** Architecture, components, and workflow of the graphical user interface.

---

## 1. Overview

The GUI provides a visual interface for loading PCAP files, performing live network capture, viewing extracted TLS fingerprints, and interactively labeling unknown fingerprints. It is built with **PyQt6** and reuses the Python engine's parser, fingerprint, and database modules.

**Entry point:** `code/gui/main.py`  
**Main window:** `code/gui/window.py` → `TlsMonitorGui`  
**Worker threads:** `code/gui/workers.py` → `PcapWorker`, `LiveCaptureWorker`

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  QApplication (main.py)                                         │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  TlsMonitorGui (QMainWindow)                              │ │
│  │                                                            │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │  Control Bar (QHBoxLayout)                           │  │ │
│  │  │  [Load PCAP] [Cancel] [Save PCAP] [Clear Records]   │  │ │
│  │  │  [Refresh Interfaces] [Interface ▾] [BPF Filter]    │  │ │
│  │  │  [Start Live Capture] [Label Fingerprint]            │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │                                                            │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │  QTableWidget (8 columns)                            │  │ │
│  │  │  Role | Source | Destination | SNI | JA3 | JA4 |    │  │ │
│  │  │  JA3 Match | JA4 Match                               │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │                                                            │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │  QTextEdit (Details Pane — read-only, fixed height)  │  │ │
│  │  │  Displays selected row metadata + raw JA3 string     │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─────────────────────────┐  ┌────────────────────────────────┐│
│  │  PcapWorker (QThread)   │  │  LiveCaptureWorker (QThread)   ││
│  │  ├─ read_pcap()         │  │  ├─ AsyncSniffer               ││
│  │  ├─ FingerprintDB       │  │  ├─ TCPReassembler             ││
│  │  └─ rowExtracted signal │  │  ├─ FingerprintDB              ││
│  │                         │  │  └─ rowExtracted signal        ││
│  └─────────────────────────┘  └────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Provide a graphical interface for TLS fingerprint analysis |
| **Design Choice** | PyQt6 with QThread workers communicating via signals/slots |
| **Reason** | PyQt6 provides native-looking widgets, a mature event loop, and thread-safe signal/slot communication. Worker threads prevent the GUI from freezing during long PCAP processing |
| **Alternative Considered** | Tkinter (simpler but less polished), web-based UI (Flask/Streamlit), terminal UI (curses) |
| **Trade-off** | PyQt6 is a heavy dependency (~80MB) and requires a display server, but provides professional-quality UI with minimal custom widget code |

---

## 3. Worker Threads

### 3.1 `PcapWorker` (Offline Analysis)

**File:** `workers.py`, lines 59–93

The `PcapWorker` runs the Python engine's `read_pcap()` generator in a separate QThread:

```python
class PcapWorker(QThread):
    rowExtracted = pyqtSignal(dict)       # Emitted for each handshake found
    captureFinished = pyqtSignal(str)     # Emitted with stats summary
    errorOccurred = pyqtSignal(str)       # Emitted on exception

    def run(self):
        fingerprintDb = FingerprintDB(str(self.dbPath))
        captureStats = CaptureStats()
        for result in readPcap(self.pcapPath, captureStats):
            if not self.isCapturing:
                break
            if result.client_hello:
                self.rowExtracted.emit(clientPacketData(result, result.client_hello, fingerprintDb))
            if result.server_hello:
                self.rowExtracted.emit(serverPacketData(result, result.server_hello, fingerprintDb))
        self.captureFinished.emit(captureStats.summary())
```

### 3.2 `LiveCaptureWorker` (Live Sniffing)

**File:** `workers.py`, lines 95–164

The `LiveCaptureWorker` uses Scapy's `AsyncSniffer` for non-blocking packet capture:

```python
class LiveCaptureWorker(QThread):
    def run(self):
        self.sniffer = AsyncSniffer(
            iface=ifaceArg,
            filter=self.bpfFilter,
            prn=self.processLivePacket,   # Called for each packet
            store=False                    # Don't accumulate in memory
        )
        self.sniffer.start()
        while self.isCapturing:
            self.msleep(100)              # Poll for stop signal
        if self.sniffer.running:
            self.sniffer.stop()
```

Each captured packet is processed by `processLivePacket()`, which feeds it through the `TCPReassembler` and emits `rowExtracted` signals for complete handshakes.

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Process packets without blocking the GUI event loop |
| **Design Choice** | QThread workers with signal/slot communication |
| **Reason** | PyQt6's signal/slot mechanism is thread-safe and integrates naturally with the Qt event loop. Emitting `rowExtracted(dict)` from the worker triggers `appendTableRow()` in the GUI thread without explicit locking |
| **Alternative Considered** | `QRunnable` + `QThreadPool`, or Python `threading` + `queue.Queue` |
| **Trade-off** | QThread is heavier than raw threads but provides built-in `msleep()`, `isRunning()`, and `wait()` methods that simplify lifecycle management |

---

## 4. Signal-Slot Data Flow

```
PcapWorker.rowExtracted(dict)  ──signal──►  TlsMonitorGui.appendTableRow(dict)
                                                    │
                                                    ▼
                                          Insert row into QTableWidget
                                          Update rowCache list
                                          Auto-scroll to bottom

TlsMonitorGui.itemSelectionChanged  ──signal──►  displayRowDetails()
                                                    │
                                                    ▼
                                          Show metadata in QTextEdit
                                          Enable/disable Label button

TlsMonitorGui.labelButton.clicked  ──signal──►  labelSelectedFingerprint()
                                                    │
                                                    ▼
                                          QInputDialog for name
                                          db.enroll() to Redis + JSON
                                          Update table cell
```

---

## 5. Row Data Format

Each row emitted by workers is a Python dictionary:

```python
{
    "role": "Client" | "Server",
    "source": "192.168.1.1:54321",
    "destination": "93.184.216.34:443",
    "sni": "example.com" | "N/A",
    "ja3Hash": "ada70206e40642a3e4461f35503241d5",
    "ja4Hash": "t13d1516h2_8daaf6152771_e56270d44002",
    "ja3Match": "curl" | "Unknown",
    "ja4Match": "curl" | "Unknown",
    "fingerprintKind": "ja3" | "ja3s" | "ja4" | "ja4s",
    "fingerprintHash": "<the hash to enroll if labeling>",
    "ja3Raw": "771,4865-4866-4867,0-10-11,23-24-25,0",
}
```

### Color Coding

- **Client rows:** Light green background (`QColor(0, 255, 0, 20)`)
- **Server rows:** Light blue background (`QColor(0, 0, 255, 20)`)

---

## 6. Fingerprint Labeling Workflow

1. Analyst selects a row with "Unknown" in the JA3 Match or JA4 Match column
2. The "Label Fingerprint" button becomes enabled
3. Analyst clicks the button → `QInputDialog` prompts for a verified client/server name
4. On confirmation:
   - `FingerprintDB.enroll()` persists the label to Redis and JSON
   - The table cell is updated with the new label
   - The details pane refreshes

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Allow analysts to label unknown fingerprints interactively |
| **Design Choice** | In-GUI dialog with immediate database persistence |
| **Reason** | The GUI provides visual context (source/destination, SNI, raw JA3 string) that helps the analyst make an informed labeling decision. Immediate persistence ensures the label is available for subsequent lookups |
| **Alternative Considered** | Batch labeling via CSV import, or a separate labeling tool |
| **Trade-off** | Interactive labeling is slower for bulk operations but ensures each label is verified by a human analyst with full context |

---

## 7. Interface Discovery

The interface dropdown is populated using Scapy's `get_working_ifaces()`:

```python
def populateInterfaces(self):
    self.interfaceDropdown.clear()
    self.interfaceDropdown.addItem("Any (All Interfaces)", "Any")
    for iface in get_working_ifaces():
        self.interfaceDropdown.addItem(iface.name, iface.network_name)
```

When "Any" is selected, the live capture worker captures on all working interfaces simultaneously:

```python
if self.interfaceName == "Any":
    ifaceArg = [iface.network_name for iface in get_working_ifaces()]
```

---

## 8. PCAP Export

The GUI supports saving captured traffic:

- **Live capture:** Saves accumulated packets via `scapy.wrpcap()`
- **Loaded PCAP:** Copies the original file via `shutil.copyfile()`

```python
def savePcapFile(self):
    if self.capturedPackets:
        wrpcap(savePath, list(self.capturedPackets))
    elif self.loadedPcapPath:
        shutil.copyfile(self.loadedPcapPath, savePath)
```

---

## 9. Graceful Shutdown

The `closeEvent` override ensures workers are stopped before the window closes:

```python
def closeEvent(self, event):
    if self.pcapWorker and self.pcapWorker.isRunning():
        self.pcapWorker.stopCapture()
        self.pcapWorker.wait()
    if self.liveWorker and self.liveWorker.isRunning():
        self.liveWorker.stopCapture()
        self.liveWorker.wait()
    event.accept()
```

---

## 10. Module Dependencies

```
code/gui/main.py
  ├─ code/gui/window.py  (TlsMonitorGui)
  │    ├─ code/gui/workers.py  (PcapWorker, LiveCaptureWorker)
  │    │    ├─ code/python/src/capture.py  (read_pcap, TCPReassembler)
  │    │    ├─ code/python/src/ja3.py      (compute_ja3_hash, etc.)
  │    │    ├─ code/python/src/ja4.py      (compute_ja4_string, etc.)
  │    │    └─ code/python/src/db.py       (FingerprintDB)
  │    └─ code/python/src/db.py           (FingerprintDB — for enrollment)
  └─ PyQt6, scapy
```

The GUI adds `sys.path.insert(0, str(pythonEngineDir))` to import from the Python engine directory without requiring package installation.
