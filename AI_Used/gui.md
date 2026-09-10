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

---

**Prompts in Order**

**Session 1**

1. > I would like to start building a native desktop app for this application. What should I use to do that?

2. > Why PyQt6? Why should I not go for something like a HTML based frontend?

3. > If we build the PyQt6 thing first, then can we wire it to both the python pipeline and the C++ pipeline? Because they are currently working on the C++ one. (It mostly works). Can we build one unified dashboard, and then hook up either, whichever one we want? and if we can, I want to start work with PyQt6. Tell me how to set it up, and make the interface.

4. > Let's keep it to Python backend for now, as the CPP backend has issues about Linux and Windows differences.

5. > Restructure the files as I have put them in separate directories as: root - code - gui.

6. > Hmm it only works with some pcap files. If the pcap file is empty, then it raises and error and the gui crashes.

7. > Separate the logic into different files. Atleast 2, keep main and UI separate. Also I feel like we should have another file for listening to the lower layers of the codebase.

8. > I tried running as administrator. These are the listed interfaces. I have also opened up different sites looking for something. Thing is when I open up wireshark, I can see thousands of packages coming in. What might be the issue?

**Session 2**

9. > We have this project for TLS fingerprinting, which I will be uploading the folder for. I want you to go over it. I am building the GUI folder, but the problem is that I cannot see any new records showing up when I press the start live capture button. Can you please tell me how I can fix that? what I want you to do is that you need to go over all the files, see how they connect, understand the architecture, reiterate and go over everything again, then you need to see what is going wrong with the GUI.

10. > which interface? I have tried confirming with wireshark, but as you can see in the second screenshot, it is hard to decipher.

11. > Okay so, I think it works, but there are two problems. 1) I feel like we should display friendly names for the interfaces. How should I map these to their friendly names? 2) Matched Client is always unkown. Is this some problem with the DB. I want you to take a deep look and tell me. Is it a problem I have because I am on Windows?

12. > 1) Need a way to clear all records from the UI. A button on the top to clear it. 2) Option to save the captured packets as a pcap file 3) Currently you can click fields and edit them with your keyboard lol. We dont want that.

13. > I tried adding an option for "Any" interface here, but this is broken. Where did I go wrong?

14. > I dont understand. The line you told me to remove just doesnt exist, and yet the application just exits when you stop live capturing.

**Session 3**

15. > Yo we are working on this TLS fingerprinting project. With respect to the GUI, Claude gave these bugs. Please look at the attatched markdown. Can you please go over them? Look at how important these suggestions by Claude are as well. First I want you to go over all the files, understand the architecture. Then give me updated code to fix them. Also I want translucent green colour on the hello messages sent by the client and blue colour coming to the client. Take all the time you need.

16. > Problems: On stopping live capturing, the application shuts down. I dont want that. Also, it says refresh Ifaces? why abbreviate? Also what is a BPF Filter?

17. > When I hit stop live capture, the application just quits. Please tell me how to fix that, and if you need any additional files. Also can you reduce the opacity of the green and the blue? Too harsh.

18. > Okay now we need 2 big new things. We need to generate timestamps for each record as they are fed into the gui. My reasoning for generating the timestamp in the gui layer is because a hello message can be more than one packet and it might be harder in the previous layers. So I feel its good enough to generate a timestamp in this layer. Do not show it as a separate field, but maybe it can be displayed on the bottom on the right hand side if you click a record? Also I need a button to open up an analytics panel. This can open up from the right hand side. In it you will see a pie chart of the different matched clients. So it could be like curl, google etc etc. Using the JA3 JA4 Matches. Also I need a line chart which will track the number of messages as time progresses. Also, when you are live capturing, would it be possible to update these graphs every second for example? Use your jurisdiction. For the layout, I want it to possibly be a panel that slides in from the left on top of the existing UI, and the pie chart is on the bottom, the line chart is on the top, or maybe we can have different tabs for them. Do whatever works better. Take your time. I suppose it would be best if we created a new python file for it no?

19. > problems: The graph looks like shit. Currently its just a white background. Can it somehow be system specific? Like my system is dark and the main window is dark for me, however for my friend whose system is light, the main window is white. So I want a dark background on a dark system and a light background on a light system (If possible) Also, the line graph is stupid? The X axis is not time consistent. It looks like you are adding a X axis value on every new timestamp being added, which makes the time difference between successive timestamps redundant.

20. > New problem: I want the actual window to be squeezed to the right when I press the analytics button, because that is hiding important information. So it will kinda be like a sidebar.

21. > I tried getting the redis db up on WSL, but it's in light mode somehow, and these are the only two interfaces it shows :(

22. > Here is the GUI folder. Drastic changes need to happen. The analytics thing breaks on different screen sizes. It pushes the buttons out so you cannot use them. Restructure everything. All I want is on clicking Analytics, I want a separate window to open, which can be closed like any other window. This will only have the pie chart. Remove the line chart completely. Also I want the pie chart to look nice as possible.

23. > Go over everything again. I have changes some colour schemes and namingConventions. Check for redundancies or extra fluff. Clean up code and we can be done.

23. > Here are all the prompts I used in creating the gui. Format them nicely so I can put them into a markdown file.