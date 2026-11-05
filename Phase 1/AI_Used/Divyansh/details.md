# AI Usage Documentation

**Tools**
* **Google Gemini**

---

**Workflow & Thought Process**
I used Generative AI throughout the process. Conversing with it about what should be done, what it thinks should be done, to compare how to do things better, and generating code.

* **Architectural Evaluation** Initial planning involved evaluating suitable frontend frameworks. AI was used to weigh the performance trade-offs of lightweight native desktop frameworks (PyQt6) against web-based frontends (Electron/HTML).

* **Cross-Platform Environment Diagnosis:** The rest of the engine (Built in C++ and Python) was created for UNIX based systems in mind. I used AI to diagnose how I could possibly get it working on Windows, and errors with WSL.

* **Iterative UI/UX and Data Visualization:** Designing the visualisation sidebar (and later window) took many iterations of back and forth with AI and fellow team members.

* **Code Auditing:** AI was used to trace subtle runtime exceptions, such as variable shadowing, and to flesh out naming conventions.

---

**Step-by-Step Details**

* **Stage 1: Technology Selection and Initial Scaffolding**
  * **Problem:** Identifying a suitable UI stack capable of handling real-time packet streams without introducing excessive memory overhead.
  * **Contribution:** Compared native frameworks (PyQt6) against web-based stacks. Outlined a modular architecture separating the GUI entry point (`main.py`), window definitions (`window.py`), and background listeners (`workers.py`).
* **Stage 2: Packet Capture Pipeline and Concurrency**
  * **Problem:** Integrating Scapy's packet sniffing routines into the interface without blocking the GUI thread or dropping incoming TLS handshakes.
  * **Contribution:** Implemented asynchronous workers (`PcapWorker` and `LiveCaptureWorker`). Wired thread-safe communication using `pyqtSignal` for incremental table updates (`rowExtracted`) and task completion notices.
* **Stage 3: Network Interface Resolution and Database Integration**
  * **Problem:** Raw network interface GUIDs were unreadable in the UI, client matches constantly evaluated to "Unknown" on Windows environments, and live capture was constrained by WSL virtual networking.
  * **Contribution:** Replaced cryptic system GUIDs with user-friendly network adapter names using `get_working_ifaces()`. Diagnosed missing Redis connections on Windows systems and explained database seeding behaviors from JSON fallbacks. Guided the networking trade-offs between WSL2 (isolated NAT switch, virtual `eth0`) and Windows-native Scapy packet capture with Npcap.
* **Stage 4: UI Refinement and Concurrency Bug Fixes**
  * **Problem:** The application crashed silently upon pressing "Stop Live Capture", table cells were unintentionally editable, and visual feedback lacked clarity.
  * **Contribution:** Diagnosed a critical bug where `self.isRunning` boolean variables shadowed PyQt’s native `QThread.isRunning()` method, causing unhandled type errors during thread termination. Renamed internal state variables to `self.isCapturing`. Configured table protections (`ItemIsEditable` disabled) and added features to clear records and export captured packets directly to `.pcap`. Implemented role-based row shading (soft alpha green for Client Hello, soft alpha blue for Server Hello) with softened opacity.
* **Stage 5: Telemetry, Timestamps, and Analytics**
  * **Problem:** Fingerprint matches lacked contextual analytics, timestamps were missing from the UI layer, and early slide-in sidebar designs broke the primary layout on different monitor resolutions.
  * **Contribution:** Injected timestamps into incoming packet records directly at the GUI ingestion layer, exposing them in the metadata inspection pane. Iterated on chart implementations: transitioned from an unstable dual-chart sidebar (line chart + pie chart) to an independent window. Rebuilt the visual display into a donut chart with automatic OS dark/light mode selection.
* **Stage 6: Code Audit and Cleanup**
  * **Problem:** Ensuring final scripts were free of redundancy and formatted consistently before project submission.
  * **Contribution:** Removed dead animation references and ensured consistent `camelCase` variable conventions.