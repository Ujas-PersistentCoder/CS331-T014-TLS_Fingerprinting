## Tools
1. Google Gemini
2. 

## Prompts

1. [I gave context of the project] The thing I would like to add is that I'll have to do it for both. We'll definitely have the live one, but before that, we'll also have the J3 get a pcap file. We can also think about that: we can save it into a pcap file as well, while we can do it live as well. We have to implement both. If you need to make two different files for captioning, that's also fine, but you tell me how good. Let's start. 

2. Another thing: sorry, I have the structure as follows:I have the folder CPP.
Inside that, I have the include folder.
Inside that, I have TL SFP.
Inside that, I have capture.hpp, db.hpp, and j3.hpp.
Similarly, on the include hierarchy, I have the src folder, which contains capture.hpp. Tell me whether I have to write code in that fashion. 

3. (base) ➜  cpp git:(main) ✗ sudo ./tlsfp_capture -i wlan0
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

7. (base) ➜  cpp git:(main) ✗ mkdir -p build && cd build
(base) ➜  build git:(main) ✗ cmake ..                                        
-- The CXX compiler identification is AppleClang 21.0.0.21000101
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
CMake Error at /opt/homebrew/share/cmake/Modules/FindPackageHandleStandardArgs.cmake:290 (message):
  Could NOT find PkgConfig (missing: PKG_CONFIG_EXECUTABLE)
Call Stack (most recent call first):
  /opt/homebrew/share/cmake/Modules/FindPackageHandleStandardArgs.cmake:654 (_FPHSA_FAILURE_MESSAGE)
  /opt/homebrew/share/cmake/Modules/FindPkgConfig.cmake:562 (find_package_handle_standard_args)
  CMakeLists.txt:9 (find_package) 

8. So the data is kept in my CPU and updated as we go on, so we are just checking, right?

9. Tell me if this code is correct for getting multi packet client hello and server hello as well. Tell me if this is completely correct 

10. Great now how to test this up? 

11. How to make ctest for this like getting some determined outcome of all the c++ files we have written to test if they are working correctly

12. how to know if this code is correct? can you help me to test this code programatically even maybe through ctest if necessary but I need to know if this is completely correct 

13. I also have ja3 and ja3s which I need to test, so that is also important, I will need to do the best mechanisms to test the code. Like there can be multiple tests right? I need to create unit tests for each one of them, maybe 1 testing the ja3 logic, 1 testing the ingestion of different agents, one testing client hello and server hello which is kept in multiple packets and a lot of edge cases, tell me what can I do to do this. I will give you more context if needed. I already have a cmake file and maybe we can create ctest here so that I can I can be sure that each and every part of my project works independently and also can work as a pipeline 

14. I have to write ctests for this and then for more......Tell me what can we write and help me to implement that

15. (base) ➜  TLS-Fingerprinting git:(main) cmake -B build -S . -DBUILD_
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

3. Debugging the interface in mac

4. I was discussing whether to write the code in cpp or in python to understand that what will be better.

5. I was brainstorming about GREASE values so I was trying to learn about the GREASE values.

6. I found a bug in the codebase that it will not be able to handle packets if they span multiple packets. So I asked AI to fix it up. Then I was asking it to not use strings and vectors because the system might get slower in allocating these datastructures.

7. There were some issues with some packages so I asked about it.

8. I asked if the current implementation is good. 

9. I gave the code to AI and asked it to tell me what the code is not doing currently

10. I asked about different ways to test the pipeline and the functions

11. I asked about ctests

12. I asked about testing

13. I asked AI to give me the ctests so that I can perform unit test on the codebase and verify the code. 

14. I changed the approach because the tests were not very clear to me so I decided to review the ctest code on the go. 

15. I got a error in the ctests so I was trying to figure that out

16. I gave some I ideas to AI to implement in the ctest. 

17. Instead of using AI generated strings to test, I decided to switch to repositories and standards. 

18. Again reiterated on the unit tests

19. Used AI to provide me with the code to beautify the cout printed by the C++ program for better readability. 