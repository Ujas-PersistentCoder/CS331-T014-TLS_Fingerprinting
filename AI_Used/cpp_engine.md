## Tools

1. Google Gemini

## Prompts

1. [I gave context of the project] The thing I would like to add is that I'll have to do it for both. We'll definitely have the live one, but before that, we'll also have the J3 get a pcap file. We can also think about that: we can save it into a pcap file as well, while we can do it live as well. We have to implement both. If you need to make two different files for captioning, that's also fine, but you tell me how good. Let's start.

2. Another thing: sorry, I have the structure as follows:I have the folder CPP.
   Inside that, I have the include folder.
   Inside that, I have TL SFP.
   Inside that, I have capture.hpp, db.hpp, and j3.hpp.
   Similarly, on the include hierarchy, I have the src folder, which contains capture.hpp. Tell me whether I have to write code in that fashion.

3. (base) ➜ cpp git:(main) ✗ sudo ./tlsfp_capture -i wlan0
   Password:
   Sorry, try again.
   Password:
   Error opening pcap target: wlan0: No such device exists (No such device exists)

4. we will move ahead with c++, we will send all the data for each which is needed for JA3/JA3S union JA4/JA4S, tell me what to do and how to do this

5. Can I not do the grease value filtering in the capture.cpp as I was thinking about keeping the ja3.cpp and stuff away from cleaning and stuff, I want that to be clean

6. This is a code for packets capturing, the flaw this has is that if a client hello or server hello file ranges over more than one packet, then my code is unable to capture that. I need to implement this first. Tell me what logic you are thinking of using. There are some things:I am okay to add code, but not very okay to remove code.
   The uncommented code is something maybe we can use.
   We have different things. There are limitations for IPv4 and IPv6, so we have to keep all of these ports working and implementable.
   I think that IPv4 and IPv6 are currently both handled in the code which I have shared, so I think we can use that implementation only. We are using some struct, right? We are using struct IPs or something. We can just use that because adding strings or arrays will add a lot of memory we'll have to allocate on the heap, and it would lead to a lot of latency, which I don't want.

7. (base) ➜ cpp git:(main) ✗ mkdir -p build && cd build
   (base) ➜ build git:(main) ✗ cmake ..  
   -- The CXX compiler identification is AppleClang 21.0.0.21000101
   -- Detecting CXX compiler ABI info
   -- Detecting CXX compiler ABI info - done
   -- Check for working CXX compiler: /usr/bin/c++ - skipped
   -- Detecting CXX compile features
   -- Detecting CXX compile features - done
   CMake Error at /opt/homebrew/share/cmake/Modules/FindPackageHandleStandardArgs.cmake:290 (message):
   Could NOT find PkgConfig (missing: PKG_CONFIG_EXECUTABLE)
   Call Stack (most recent call first):
   /opt/homebrew/share/cmake/Modules/FindPackageHandleStandardArgs.cmake:654 (\_FPHSA_FAILURE_MESSAGE)
   /opt/homebrew/share/cmake/Modules/FindPkgConfig.cmake:562 (find_package_handle_standard_args)
   CMakeLists.txt:9 (find_package)

8. So the data is kept in my CPU and updated as we go on, so we are just checking, right?

9. Tell me if this code is correct for getting multi packet client hello and server hello as well. Tell me if this is completely correct

10. Great now how to test this up?

11. How to make ctest for this like getting some determined outcome of all the c++ files we have written to test if they are working correctly

12. how to know if this code is correct? can you help me to test this code programatically even maybe through ctest if necessary but I need to know if this is completely correct

13. I also have ja3 and ja3s which I need to test, so that is also important, I will need to do the best mechanisms to test the code. Like there can be multiple tests right? I need to create unit tests for each one of them, maybe 1 testing the ja3 logic, 1 testing the ingestion of different agents, one testing client hello and server hello which is kept in multiple packets and a lot of edge cases, tell me what can I do to do this. I will give you more context if needed. I already have a cmake file and maybe we can create ctest here so that I can I can be sure that each and every part of my project works independently and also can work as a pipeline

14. I have to write ctests for this and then for more......Tell me what can we write and help me to implement that

15. (base) ➜ TLS-Fingerprinting git:(main) cmake -B build -S . -DBUILD\_
    TESTING=ON
    CMake Error: The source directory "/Users/satyakammishra/Documents/Github Repos/TLS/TLS-Fingerprinting" does not appear to contain CMakeLists.txt.
    Specify --help for usage, or press the help button on the CMake GUI.

see, you do not have a lot of context, do not guess. You are a senior computer networks engineer. Take all the context you need by giving me the grep commands the test_fingerprint is completely empty you need the context then give me the grep commands and then will work on the next steps only after we understand the codebase. Lets start. [I then pasted the code as asked by AI]

16. I want to have more strict tests like, Smallest packet possible is working through the parser test, Largest packet working, The multiple packet client hello server hello reassembly working, Above is working for out of order packets as well.

17. Tell me about some repos or databases or something from which I can get some tests which are really good to test my code. it will be trusted more than a LLM right

18. I need to write unit tests for my team, I will have 2 kinds of unit tests, one will be from the functions here like I will try to test each and every function in here (There are many more files by the way) ja3, ja4 but we will go one by one. Getting as many and as detailed tests as possible. The second kind will be using the things available in GitHub like salesforce/ja3 and stuff so that they have a lot of credibility. I need to write deterministic tests.

Currently, with my architecture, whatever signals are coming to my laptop, whatever packets are coming to my network card, I am able to intercept them. I have different modes of intercepting them, like Ethernet and stuff. I can intercept different kinds of packets, and I have done test fingerprints or CBB. Although it's not just for fingerprints, it is for testing everything. I am writing C tests for that.

Whenever a packet comes, I am mostly interested in the client hello and the server hello only. After that, what I am doing is scraping. If there are multiple packets, if the packet length is too big, or if there are packets of multiple sizes, I'm handling the auto stuff, like IP6, IP4, and more things like that. We are converting it into GA3, then checking it against a database, and then telling which kind of protocol it was. That is all it is.

https://github.com/salesforce/ja3/tree/master/python see this repo, I am thinking baout using some standard hashes from here to test my engine rather then ai gussing the hashes any good locations from where I can do this. Like the tests you gave me how can I be sure that they might not be a mistake by AI

19. Kindly see this. This is how it is getting printed for now. There are a lot of stdout messages in my CPP folder, and I want to try to make it more beautiful. I want the CLI to be more beautiful. Tell me what can be done or what we should do. I think you should inspect using `grep` to find where the stdout is and tell me exactly what code to change so that this gets beautified more. I have capture.cpp, db.cpp, ja3.cpp, ja4.cpp, main.cpp, parser.cpp

## Thought Process:

Majorly the code is written completely by AI and reviewed by us. However instead of saying that do my assignment for me, we have made the codebase stepwise so that we can test at each point and verify that the system is working. We have used AI in such a way that we tell it the logic and in turn it gives us the code that follows that logic.

## Step-by-step details

1. and 2. I first tried to understand the requirement of the project and verified the stucture of the codebase that will it be the best possible design

2. Debugging the interface in mac

3. I was discussing whether to write the code in cpp or in python to understand that what will be better.

4. I was brainstorming about GREASE values so I was trying to learn about the GREASE values.

5. I found a bug in the codebase that it will not be able to handle packets if they span multiple packets. So I asked AI to fix it up. Then I was asking it to not use strings and vectors because the system might get slower in allocating these datastructures.

6. There were some issues with some packages so I asked about it.

7. I asked if the current implementation is good.

8. I gave the code to AI and asked it to tell me what the code is not doing currently

9. I asked about different ways to test the pipeline and the functions

10. I asked about ctests

11. I asked about testing

12. I asked AI to give me the ctests so that I can perform unit test on the codebase and verify the code.

13. I changed the approach because the tests were not very clear to me so I decided to review the ctest code on the go.

14. I got a error in the ctests so I was trying to figure that out

15. I gave some I ideas to AI to implement in the ctest.

16. Instead of using AI generated strings to test, I decided to switch to repositories and standards.

17. Again reiterated on the unit tests

18. Used AI to provide me with the code to beautify the cout printed by the C++ program for better readability.

#####

## AI tools used : Gemini Flash Extended-thinking, (chat only)

## Primary prompts given:

# Understanding the project

1. Hey gemini, I have a networks project at hand, and we need to discuss what is the PS, what are we going to do and thoroughly plan it out

2. Project Description: Build a tool that passively captures TLS ClientHello and ServerHello messages and computes JA3/JA3S fingerprints (with JA4/JA4S as a stretch goal) to identify the client or server application/library generating the traffic. Curate a small reference database and demonstrate distinguishing real clients (browsers, curl, custom scripts) purely from their handshake fingerprint.
   Tools/Technologies: : libpcap/Scapy (or raw sockets) for capture; fingerprint computation implemented per the JA3/JA4 specifications, eBPF/XDP, Packet/Flow Generators like TRex, KV-stores (Redis, Valkey).
   Expected Outcome: Demonstrate the working JA3/JA3S fingerprint extractor, validated against published reference JA3 hashes for known clients; A curated database correctly identifying at least 5 distinct clients/tools by fingerprint alone. Demonstrate distinguishing, e.g., curl vs. a browser vs. a custom TLS client on the wire.
   Understanding on the fingerprinting's role in security monitoring (malware C2 detection, client identification) and its limitations, including fingerprint randomization in modern browsers as an evasion technique.

3. ok lets take this step by step, why dont u first help me with understanding what the project is about, what is expected,what is the workflow etc beofre we dive in to techincal details or planning. Here is teh PS again for reference

4. hmm, and what is the tech stack we will need to build this, i mean something to sniff the packets, then something to process them, the fingerprint engine. Then what about the database, and live demonstration

5. hmm, we are a team of 6, and we have two weeks to complete things. I think we are more than required. So can we do something like two guys work on building the fast prototype using python and others try to build the perfect high throughput product. Or should all of us work on the same part? what would your idea be of delegating work to a team of 6 for this project. We can even work in pairs or groups

6. lets try and explain the project in layman terms, the entire worklfow like some connection will be tried to establish, packets will be caught, then .........and so on

7. lets try and explain the project in layman terms, the entire worklfow like some connection will be tried to establish, packets will be caught, then .........and so on

8. can we somehow handle ECH or fingerprint randomisation

# Friction before coding

1. this is the folder structure we are thinking of using, ofc we can make cahgnes as required. My friend is working on the ingestion of packets/data in c++. And i am in charge of the JA3 and later the JA4 implementation in c++. Lets focus on this. We have three stages right, ingestion,extraction and getting the JA3 string. Lets say he gives me that packet, what will be the format....or maybe we should first go with pcap files

2. though i trust you, is there somewhere official where i can look up all these data that comes in a clienthello message and the algorithm to get the JA3 string. Or maybe we can somehow get a packet of our own to actually be able to see it

3. ok, as i said i am very new to this, so we take this very small steps at a time. first lets get a real example for ourselves so we can work better.....explain to me everything we do, i mean even the flags of acommnaf u ask me to run

4. the .pcap file is not human readable? then how will we extract the data from that

5. ok, lets get back to the project, i gave u the current file strucutre. Lets start working on it, assume we have a .pcap file for now and we start with the extraction and then once we are confident on the extraction, we will move to the JA3 implementation

6. wait, first lets understand carefully and minutely what we are doing. what code we have written, even before we test it

7. hmm, i think it will make more sense to me if we can see it thourgh a example, can we somehow use our sample pcap file and see where each data we need is there and how can we ....................

8. Wait.....we have the plan locked in right, so lets track back a little, lets start from the vrey basic. what is tls, why is it....then we take an example tls handshake and see its contents.....then i think we will be better equipped to start thing perfectly

9. hmm, now how does this work for our project. Particularly, i was thinking of monitoring both client Hello and server hello packets. Here are some of the questiosns i need answers to
   We will need seperate engines for Client Hello and Server Hello right....
   Can we somehow just capture the TLS packets, so we dont waste time compute and memory on others as we will need to be very very fast
   What other information can we proide in the GUI or use for ourselves based on just the TLS packets, both client and server, probably showing the encryption strategy etc or naything useful
   How do handle these things like missing segments, or we dont need to worry about them?

# Coding

1. Umm. my friend is looking after the ingestion part....so we can start with the assumption that hi gives us the tls packet to analyse, ofc in what format i can tell him

2. Hmm. so the if else condition of ClientHello or ServerHello can be embedded directly into the parser right, so the workflow becomes, capture captures the packet, and sends to parser. The parser cleans out the grease, and based on whether it is a clienthello or server hello, will call the requried function, written right into the parser, but calling the JA3 file for JA3 or JA3S conversion based on the type. Then we will call the db file to cross check with the database. And the main file orchestrates this entire process

3. OK here is what my friend he has done, lets have a look at it, understand it, and if required make changes to it. Then we can start our work on our part as per our planning..........

4. i have kept the default link_type 0 for now, so we can find out if it actually captured the type or not, also what does cstdint do

5. are there only these three types of link headers?

6. why are we skipping the ipv6 for now?

7. ok before i go for the make file and the output, lets summarise the changes we made in these three files and why before testing them.

8. Lets review and strengthen what we have made till now before moving forward, deeply understanding what it does, how it works and what it misses, or anything we should be careful about

9. this zero copy handoff wont affect the pcap file storing right, since we need it now for debugging purposes

10. ok lets carefully look at the capture.cpp that will give things to the parser.cpp

11. hmm before that, lets test our current work, while also understanding what our cmake does and how, i am new to this concept of cmake or builds in c++.....

12. no i think we need to tweak our capture.cpp to also caputre serverhello messages and pass them to the parser

13. lets test our implementation till here, before that, should we also allow ipv6 addresses to come in? then we can make that modification right now

14. hmm, nice, just one question before we move to the ja3 implementation, till now whatever we have done, i beleive has no unnecessary computation or overhead except for saving the files which we want to confirm our work. Do we need the struct here or is there a better way to pass the information

15. hm right, we want to keep things feasible for the JA4 implementation too....lets do it.....then we can also start working on GREASE

16. Let's build the JA4 fingerprint implementation (sorted ciphers/exts and SHA-256 truncation).

17. hmm.....wait, i think.....lets take a break here, i will now review our work till now, and ask you for clarifications wherever i am stuck, we will take a .pcap file as a sample that i will give you copy pasting from wireshark. lets see what we have done so far, and also make notes out of our dicussion to understand things better..........ready?

18. wait before we start, what kind of packets can our current tool capture? asking becuase any request i am making thourgh my browser is not caught.......dont we want it to capture every tls packet going out or coming into the device?

19. just in case we had to make this work for windows, we would need a seperate module stack right.....otherwise there is no issue right

These are the primary prompts used while coding in the project. Later I started a new Gemini chat, got each of the file reviewed one at a time, where it pointed out some critical mistakes, and then also used this chat to debug whenever a issue came up in testing.

## Thought process and AI-Integration

Initially used AI (gemini) to get a better understanding of the project, and references to related official documentations. Further used it to verify the pipeline, workflow and work division begin thought of. Following this, used it for coding files part by part, while understanding the code and challenging the decisions made, and improving upon them. Later used it to debug-understand terminal outputs/errors while testing, code review and finally for addressing failures during final testing.

I treated AI (Gemini) as a technical pair programmer:

- Navigating Specs: Broke down dense RFCs (TLS 1.3, GREASE, JA4) and checked wire-format nuances before writing code.

- Challenging Architecture: Vetted the pipeline design early—pushing to replace heap allocations with zero-copy string views and keep the packet processing cache-friendly.

- Building Incrementally: Wrote the C++ modules step-by-step, understanding the tradeoffs behind each structure instead of just accepting generated blocks.

- Low-Level Debugging: Used it to bounce ideas off when things broke—troubleshooting CMake flag parsing, handling TCP sequence reassembly edge cases, etc

- Verification: Validated the live output against reference PCAPs to ensure our JA3/JA4 hashes matched down to the byte.
