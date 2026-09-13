### AI Tools used: Claude.ai, Google Antigravity

### Prompts:

**Claude - Report**: I'm starting to write the report for TLS fingerprinting project. Here is a rough list of areas to discuss in the report (not exhaustive): - Introduction of the project (what is TLS fingerprinting. ) - History/theory - What have we done - Our approach - Our design decisions and why we made them (instances of working towards one approach and switching to another for some reasons, if there are any instances) - C++ and Python high-level implementation details and a subjective comparison of the two engines - Benchmarks and results (important) - Future scope - One of the points: client and server hashes can be combined to get even broader set of information and stronger malware detection - "Understanding on the fingerprinting's role in security monitoring (malware C2 detection, client identification) and its limitations, including fingerprint randomization in modern browsers as an evasion technique." This exact line is in the description of the project list, so we need a well-written answer for that.

**Google Antigravity - Core documentation**: Go through our entire codebase, understand our implementation from the ground up and add detailed documentation inside report/ folder at project root. This documentation should be formal, well-structured.For every important component, document:
Requirement
↓
Design choice
↓
Reason
↓
Alternative considered
↓
Trade-off
For anything you don't know, LEAVE IT EMPTY. Don't assume anything. Explain the conceptual chain (wherever applicable). Connect the code implementation with the computer networks theory. Plan first.

### Thought process and integration:

First asked AI to build up the report in the desired format with context to the entire repo. Then 3-4 of us sat together reviewing each section iteratively and making necessary changes.

### For PPT, only the attached image was generated using gemini, otherwise no AI was explicitly used.
