# Documenting AI usage in project README

**Created:** 9/8/2026 10:11:02  
**Updated:** 9/8/2026 10:11:17  
**Exported:** 9/13/2026 15:10:04  
**Link:** [https://claude.ai/chat/9b62d92f-a028-4160-be3f-ba8bcd8bd634](https://claude.ai/chat/9b62d92f-a028-4160-be3f-ba8bcd8bd634)  

## User:

> 9/8/2026 10:11:09

Want to add a mention of AI usage in project README to avoid plagiarism

## Assistant:

> 9/8/2026 10:11:17

Here's a concise disclosure section you can drop into your README:

```markdown
## AI Usage Disclosure

Portions of this project (code scaffolding, debugging assistance, documentation 
drafting, and test case generation) were developed with the assistance of AI 
tools (Claude). All AI-assisted code was reviewed, tested, and validated against 
known-answer test vectors (Salesforce JA3 reference values, FoxIO JA4 test 
vectors) by the team before inclusion. The core protocol understanding, 
architectural decisions, and validation methodology are the team's own work.
```

A few things worth thinking about before you paste this in:

1. **Be specific if your professor asks for granularity.** "Portions" is vague — if your course has a strict AI policy, some professors want per-file or per-module attribution (e.g., "JA4 implementation in `ja4.py`/`ja4.cpp` was AI-assisted; TCP reassembly logic in `capture.py` was written by [name]"). Check your syllabus's academic integrity policy for what's actually required — don't just guess at the right level of disclosure.

2. **Don't overstate your own hand and undersell it either.** Given the volume and sophistication of code here (thread-local OpenSSL contexts, RESP protocol implementation from scratch, RFC 1982 modular sequence arithmetic), a vague one-liner is going to look thin if a grader spot-checks against the codebase. If this was substantially AI-generated and lightly reviewed, say so plainly — that's not shameful, but claiming "team's own work" for the architecture when it wasn't is the kind of thing that gets you in real trouble if it's ever contested.

3. Put it in `report/00_project_overview.md` too, not just the top-level README, since that's your actual graded documentation artifact.

Want me to draft the more granular per-file version instead, given how much of this codebase is AI-generated per your project context?

Powered by Claude Exporter (https://www.ai-chat-exporter.net)
