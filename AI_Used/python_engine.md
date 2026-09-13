# Python JA3/JA4 Engine - AI Usage Details

Tools used:

1. Claude.ai (Model: Claude Sonnet 5)
2. Google Antigravity IDE (Model: Gemini 3.1 Pro)

## Prompts:

### Claude.ai

1. Deep dive into the TLS fingerprinting project.
   - Non-technical overview of the project (what the final deliverable is roughly supposed to look, agnostic of how we decide to implement it)
   - Vague plan of action (what are the key tangible milestones)
   - Conceptual/theoretical prerequisite background (we're all learning computer networks for the first time, and we just done the super basics only for now)
   - Tech stack and tools to explore and why. Don't just mention the ones you recommend the most. Tell me all the libraries worth going over (at least surface-level)
2. Why does the problem statement mention JA4 as "a stretch"? We're thinking jumping straight to JA4, it seems straightforward enough, and it results in a much simpler DB
3. https://github.com/salesforce/ja3/tree/master Do we use this repo for the fingerprint engine, or are we expected to implement JA3 from scratch. This repo seems surprisingly shallow and straightforward, and the fact that it's in Python is raising even more suspicions of whether "this is all I need for JA3"
4. What's your recommendation of the overall tech stack? Python? C/C++? Rust? Go? Something else?
5. Does C/C++ have any benefit over Python?
6. What should be the high-level approach for the Python implementation?
7. What is the exact need for the database? Why does the project description explicitly mention Redis and Valkey? Why can't we just store the data we collect in simple JSONs or CSVs on disk?
8. We are planning two simultaneous implementations for this project - Python (backup) and C++ (if all goes well). So create a tentative folder strcture for the project repo. One `python/` folder and one `cpp/` folder. You decide the structure inside that.
9. Should I clone the salesforce/ja3 repository as a submodule? Or is there a better way to have them in my project as purely reference material? It won't be wired into my pipeline, but I need the source code for helping me write my own fingerprinting modules
10. Have a look at my Python implementation of the project. Don't dissect it line-by-line just yet, we will analyse this top to bottom. First and foremost, what are your thoughts on the first glance? At this current stage, what do you think should work as expected, and what part of it kinda shaky? Any fundamental flaws with the high-level approach?
11. How much TCP reassembly do I practically need to perform? Here's what I heard. Feel free to provide your own independent opinion on this: "Building a full TCP state machine (tracking SYN sequence numbers, handling window scaling, FIN/RST teardown) is a project unto itself and beyond the scope of a course demo tool.Full out-of-order reassembly would require buffering segments with their sequence numbers and inserting them at the correct position, handling overlapping segments, etc. This is a valid extension but not worth the complexity for this project's goals. The duplicate-detection fix alone eliminates the most common real-world corruption scenario (retransmissions being appended as though they were new data). " On the other hand, I've also heard: "But you do need a small amount of TCP reassembly logic if you want the parser to work on real captures rather than only convenient Wireshark-generated examples."
12. How can I perform real-world tests for my system? Something apart from the unit tests I'll be writing
13. This is regarding the TLS Fingerprinting project. I have made a local change in the code to wire my python implementation with the JSONs already there in main. My fingerprints.json might be better, but in the long run we'll be using those other two JSONs. That rewiring won't be visible to you, but assume it's there. Now, after those changes, I tested my code on a PCAP I recorded using tcpdump, in which I used a browser, a urllib request and requests library request to search for cloudflare.com. Here are the results. I want you to analyse them and report your observations.
14. Discuss the approach for JA4 fingerprinting in the Python engine. You can refer to the C++ implementation of the same. We _can_ copy their exact approach in Python too, but only if it makes perfect sense. Stay flexible, we're only discussing right now
15. Regarding the issues you found with the C++ engine, there have been recent pushes to the repository, have a look at the updated code and let me know if these issues have now been resolved. Also review all the code in general to look for any kind of critical bugs or mismatches.

### Google Antigravity

1. Read README.md to find the project description. I have also cloned ja3 , which is the original implementation of JA3 fingerprinting by Salesforce. Purely reference only. We are expected to write our own fingerprinting engine. We are planning two simultaneous implementations for this project - Python (backup) and C++ (if all goes well). I am only concerned about the Python implementation right now. Go through everything relevant, gather all the information you need and tell me when you think we're on the same page on this project.
2. I've created a [CONTEXT.md](file;file:///Users/pranjal/Projects/CS%20331%20CN%202026/.agents/CONTEXT.md) file in a new [.agents](directory;file:///Users/pranjal/Projects/CS%20331%20CN%202026/.agents) folder. If you want to reorganise this file elsewhere (outside the source code but in a location where you expect it to be everytime), do so. Also cleanup, add or remove anything from that file as you see fit. Create a project-wide rule to update this file as we keep working on this project.
3. Let's work on the capture layer in [python](directory;file:///Users/pranjal/Projects/CS%20331%20CN%202026/TLS-Fingerprinting/code/python). This exercise would look like me telling you what to do and you writing and explaining the code for that. We repeat this as many times as it takes for thorough understanding, plus achieving more accurate code. Don't write large snippets of code in one go. To begin with, I'd like to explore two things:
   1. Structure of a .pcap file and what part of it are we supposed to dive deep into.
   2. Comparing the two Python libraries: `dpkt` and `scapy`.
   3. Also note that live capture is out of the scope as of today. We only focus on ingesting a .pcap file and just working on that.
4. I did curl on google.com and iitgn.ac.in during the latest pcap recording, and above were the results. Can you explain these results before we move on?
5. Give me an overview of the workflow we will be adopting for TCP stream reassembly
6. "Scapy is allowed to hand you bytes, it is never allowed to interpret those bytes." Use Scapy's sniff(prn=callback) purely as a packet delivery mechanism — inside the callback, immediately pull bytes(pkt.original) (the actual wire bytes, not a re-dissected object) and feed that into the same manual parser you built for pcap files. Never touch pkt[TLS] or any Scapy dissection layer. What changes would we have to make now to our codebase?
7. I want you to work on the python implementation of this project from start to finish, or as close to the finish as you can get before you're "forced to give up" or my involvement becomes inevitable. Use the python-oneshot/ worktree, it is your playground. No restrictions. Write the best code you can. Don't overcomplicate anything, but at the same time don't simplify anything just because it will be hard for me to grasp it. If you think it is the correct, professional and well-explainable approach, go for it. Here is a high-level overview you can follow. Not a strict plan, just guidelines you may or may not choose to follow.
   (_insert plan generated based on discussions with Claude_)
   Start off with a clear plan of your own. Understand and digest my request first, and once you think everything is clear, we can kick things off. Feel free to ask any questions.
8. Can you explain everything you've done, with all the low-level implementation details and rationale
9. Move main() to main.py and remove cli.py.
10. Formal list of shortcomings identified in the current Python implementation:
    (_insert list of shortcomings identified by Claude_)
    First identify these issues in the codebase, include your own findings/extra suggestions (if any), propose a plan of action. Feel free to reject / postpone any of these if you think there is a good reason to do so. Also feel free to look for and include problems of your own in this plan.
11. I think you're underselling the need of better TCP reassembly. Based on my research, out-of-order reassembly, overlap resolution etc will be crucial. Here's my suggestion for what you should implement, but give your genuine opinion on this, feel free to push back if you can justify it.
12. Can you look at the tests you wrote and what logic is validated and you're confident won't break when real-world packets arrive? How do you suggest I should go about manually testing the current implementation?
13. Plan to expand the Python engine to compute JA4 and JA4S hashes too. Have a look at the following proposed plan (just a suggestion, flexible, change as you wish)
    (_insert plan from Claude_)
14. I just pulled some changes. Look at my comments, and also the updated code. Update the plan accordingly, if it even requires any changes post the latest pull
15. I've cloned the FoxIO JA4 repository at the "~/Projects/CS 331 CN 2026/ja4". Check out ja4/python/ja4.py, and see how we could use that to verify the fingerprints we obtain. Also inspect the rest of the repository to see if there's anything else we can use to our advantage. Also look at FoxIO's code implementation to verify our computation logic is correct. Read-only until I tell you otherwise.
16. Copy a subset of the FoxIO PCAPs (like sigalg-grease.pcapng and tls-non-ascii-alpn.pcapng) into our pcaps/ folder and write automated integration tests against them.
17. So I'm assuming JA4 is fully working now. If it's not, stop and clarify immediately. Otherwise, can you tell me how I can test the functionalities manually, and how to interpret the results?
18. I have to implement live capture in the Python engine. Reiterate the current state of affairs (relevant bits I should know about from both the python as well as the C++ engines) so that we can discuss how to proceed
19. Can you confirm that the TLS-Fingerprinting repository is fully self-sustained, and it isn't referring to files outside of the repository? It should safely run if I delete everything and clone just this repo in my machine (assuming I've pushed all my changes before)
20. Look for geniune limitations of our project
21. Explain and review the benchmarking code

---

## Thought Process

Here are the tools I used while creating the Python engine

1. Claude.ai
   - thinking exploration and research partner
   - help in making better architectural decisions
   - conceptual/theoretical understanding
   - code review
   - miscellaneous doubts and discussions
2. Google Antigravity IDE
   - Primary tool for code-generation

## Step-by-Step Details

1. Claude helped me understand what the project was about (theory), what the team had to do over the course of 3 weeks, how to structure our code, etc
2. Once the conceptual prerequisites were cleared, I moved on to Antigravity
3. I used Antigravity to work on two different branches - `main` and `python-oneshot`
   - `main` branch was where I was taking things slowly and carefully, implementing the code component-by-component and understanding the code on-the-fly
   - `python-oneshot` was where I was trying to one-shot the entire Python engine with a single, targeted prompt followed with quick follow-up changes if needed.
4. Surprisingly, the careful approach eventually transitioned into and met with the one-shot approach. So I ended up moving forward with the one-shot code after understanding it thoroughly.
5. I merged `python-oneshot` branch with `main` and continued working on the JA4 engine and live capture functionality from there.
6. Throughout this process, I was testing my engine with real-world PCAPs. Sometimes the results were too noisy and hard to interpret. That's when I would paste the results to Claude and Antigravity to help me analyse them.
