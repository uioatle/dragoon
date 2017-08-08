# Pure User Mode Deterministic Replay on Windows
This repository contains the code for my master's thesis. The included solutions are described below.

## Dragoon
This is Dragoon's recording component. In the future also the replay component will reside within this solution. The reason the recorder and replayer currently don't share the same solution is because the latter was implemented before the former. If you look at the code you'll see how chaotic it is compared to the recording component rewrite.

The projects in this solution are:
- **Dragoon:** The starting point of the recorder. You start the recorder by calling main() in main.cpp. This project is the console program that kicks off recording. This is where you'd give in command line arguments and such to decide how things should be set up and recorded.
- **DragoonDll:** The actual Dragoon recording component. It's a DLL and gets injected by the console program. The code for most of the recording happens here. Recording system calls, callbacks, and so on.
- **DragoonDllWriteWatchingReallocator:** An individual executable that frees and reallocates everything in the recordee's address space from outside the recordee to avoid chicken-and-egg kind of problems when reallocating.
- **DragoonGlobal:** Code that is global for the whole solution. Directory paths, logging, and new/delete operator replacement happens here.
- **TestExecutable:** The dummy program that was used to test the recorder's performance.
- **ThreadEventLogConverter:** Takes a raw binary recorded log from Dragoon's recording component and makes it humanly readable.
- **lib/Util:** General utility code to avoid having to write the same old over and over. The WinAPI doesn't throw exceptions, and it's tiresome to keep checking return codes... Dragoon's custom memory allocator also resides in here.

**xxHash** can be found in **DragoonDll** but is not being used as CRC32 64-bit in hardware is being used as the checksumming algorithm. It's just there because of testing. Everything else is implemented without third party libraries. Hopefully the thesis has given the reader an intuition by now why libraries are avoided in this project.

## Mirai
This is Dragoon's replay component which implements Direct Address Space Recreation. Fear not! This solution has nothing to do with the Mirai botnet, it just happened to be that I named my thesis project this and then a week later realized there was a new botnet with the same name. The name remains to avoid mixing up the code as the name is referenced throughout the solution. The code isn't as clean as the code in the Dragoon solution because I was fairly new to C++ and I didn't have time to do it properly; I had a lot of things I needed to verify and kept rewriting the same things in different ways. I've cleaned up the countless amount of commented out code, so there's nothing superfluous left in there, though. Also note that this code is heavily outdated and uses an old log format, but it's not very important.

The projects in this solution are:
- **MiraiReplayProcess:** The process in which direct address space recreation happens; the address space is torn down and replaced with that in the recorded logs.
- **MiraiReplayer:** The replay component. Execution starts at main() in main.cpp. It performs direct address space recreation on **MiraiReplayProcess** and sets up a communication channel through shared memory with said process. It then JITs basic blocks and tells the replay process what to do next.
- **MiraiReplayerDll:** In order for the replay process to have its address space recreated and code thereafter be replayed Dragoon needs to be injected as a DLL in the replay process. This is that DLL, and it is different from *Dragoon/DragoonDll* which is the DLL used for recording. This DLL helps in recreating the address space and receives commands from *MiraiReplayer* that it executes, most notably executing the JITed code before returning to *MiraiReplayer*.
- **Shared:** Contains shared code for the solution. The communication area code is shared between *MiraiReplayer* and *MiraiReplayerDll*, so it resides in here.
- **TestExecutable:** A dummy program to test replay using direct address space recreation. It does some inline assembly and makes sure the JITer is able to properly instrument the basic blocks.
- **Util:** A deleted project. It's the same as *Dragoon/lib/Util*.

The third party libraries **asmjit** and **distorm** have been deleted as they can be found online. They're used by **MiraiReplayer** to disassemble and assemble basic blocks. Everything else is implemented without third party libraries to avoid WinAPI interaction. Regardless, the replay component is much more lenient when it comes to library interaction because much of the work happens in the replayer (**MiraiReplayer**) which has its own process. Libraries are completely banned in the replay process, however.

## event_log_example_human_readable.txt
Should be fairly obvious, but this is an example of what is outputted by **Dragoon/ThreadEventLogConverter**.