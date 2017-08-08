#include "common.h"
#include "system.h"
#include "smart_handle.h"
#include "memory_region.h"
#include "windefs.h"

#include "shared.h"
#include "comm_area.h"

#include <cstdio>
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <Windows.h>

extern "C" __declspec(dllexport) void threadWaitAreaEntryPoint();

// -------------------

LPCVOID _systemReservedAllocationBases[1024] = {0};

extern "C" __declspec(dllexport) LPCVOID getSystemReservedAllocationBasesArrayAddr()
{
	return &_systemReservedAllocationBases;
}

std::set<LPCVOID> systemReservedAllocationBases; // TODO Update name, it's the TEB addresses we're interested in, this is just confusing, especially since the TEB32 isn't even aligned on allocation base!

void fillSystemReservedAllocationBases()
{
	const LPCVOID* pSystemReservedAllocationBases = _systemReservedAllocationBases;
	while (*pSystemReservedAllocationBases)
	{
		systemReservedAllocationBases.insert(*pSystemReservedAllocationBases++);
	}
}

Util::ThreadId createThreadsWithTEBsResults[1024] = {0};

extern "C" __declspec(dllexport) LPCVOID getCreateThreadsWithTEBsResultsArrayAddr()
{
	return &createThreadsWithTEBsResults;
}

extern "C" __declspec(dllexport) DWORD createThreadsWithTEBs()
{
	// TODO Catch exceptions in the whole function and return error code. Do this with all functions communicating with MiraiReplayer.
	DWORD errorCode = 0;

	std::vector<Util::ThreadId> tempThreadIds;
	std::vector<Util::ThreadId> tempThreadIdsMatchingTEBs;

	fillSystemReservedAllocationBases();
	if (systemReservedAllocationBases.empty())
	{
		errorCode = 1;
		goto exit;
	}

	for (const auto& e : systemReservedAllocationBases)
	{
		printf("Requested TEB: %p\n", e);
	}

	const DWORD maxAttempts = 1000;
	for (DWORD i = 0; i < maxAttempts; i++)
	{
		// Create temp thread.
		DWORD tempThreadId;

		if (!CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&threadWaitAreaEntryPoint, NULL, 0, &tempThreadId))
		{
			// TODO Free all threads and return error code.
			errorCode = 2;
			goto exit;
		}

		tempThreadIds.push_back(tempThreadId);

		// Check if the temp thread's TEB is one of the ones we're looking for.
		Util::Thread tempThread(tempThreadId, GetCurrentProcessId());
		const void* tempThreadTEBAddr = tempThread.ReadTEB().Self;

		if (systemReservedAllocationBases.find(tempThreadTEBAddr) != systemReservedAllocationBases.end())
		{
			printf("Found a match for TEB %p: temp thread ID %08X\n", tempThreadTEBAddr, tempThread.GetId());

			// Add the thread ID to a list.
			// TODO Could just pass the Util::Threads around, no need with all these IDs.
			tempThreadIdsMatchingTEBs.push_back(tempThreadId);
		}

		// Have we got everything we wanted? In that case just break here.
		if (tempThreadIdsMatchingTEBs.size() == systemReservedAllocationBases.size())
		{
			break;
		}
	}

	// If none of the temp threads yielded our wanted TEBs we abort.
	if (tempThreadIdsMatchingTEBs.empty())
	{
		errorCode = 3;
		goto exit; // TODO Also clean up temp threads
	}

	// Unable to reserve all the TEBs we requested?
	if (tempThreadIdsMatchingTEBs.size() != systemReservedAllocationBases.size())
	{
		errorCode = 4;
		goto exit;
	}

	// Kill the threads that didn't get us the wanted TEBs (those that were truly temporary).
	for (const auto& tempThreadId : tempThreadIds)
	{
		// If the current thread ID is one of those matching a TEB, skip.
		if (std::find(tempThreadIdsMatchingTEBs.begin(), tempThreadIdsMatchingTEBs.end(), tempThreadId) != tempThreadIdsMatchingTEBs.end())
		{
			continue;
		}
		
		(Util::Thread(tempThreadId, GetCurrentProcessId())).Terminate(0);
	}

	// Move the results into the statically allocated array.
	Util::ThreadId* pCreateThreadsWithTEBsResults = createThreadsWithTEBsResults;
	for (const auto& tempThreadIdMatchingTEB : tempThreadIdsMatchingTEBs)
	{
		*pCreateThreadsWithTEBsResults++ = tempThreadIdMatchingTEB;
	}

exit:
	// If there was an error, signal it by clearing the result buffer.
	if (errorCode != 0)
	{
		ZeroMemory(createThreadsWithTEBsResults, sizeof(createThreadsWithTEBsResults));
		createThreadsWithTEBsResults[1] = errorCode;
	}

	threadWaitAreaEntryPoint(); // TODO Ultra sloppy deluxe edition. But hey, whatever works for now...
	return errorCode;
}

// -------------------

volatile uint32_t numTempThreadsCreated = 0;
void tempThreadEntryPoint()
{
	numTempThreadsCreated++;

	Util::Thread tempThread(GetCurrentThreadId(), GetCurrentProcessId());
	tempThread.Suspend();
}

std::vector<DWORD> tempThreadIds;
extern "C" __declspec(dllexport) void reserveTEBsTemporarily()
{
	// TODO Exceptions won't help MiraiReplayer (not the DLL), need to return error codes instead?

	const uint32_t numNewThreadsRequiredToReserveTEBs = 200;
	printf("Creating %u temp threads\n", numNewThreadsRequiredToReserveTEBs);

	for (uint32_t i = 0; i < numNewThreadsRequiredToReserveTEBs; i++)
	{
		DWORD threadId;
		const HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&tempThreadEntryPoint, NULL, 0, &threadId);

		if (!hThread)
		{
			Util::ThrowExceptionWithWin32ErrorCode("Failed to create temporary thread #" + std::to_string(i));
		}

		tempThreadIds.push_back(threadId);
	}

	while (numTempThreadsCreated != numNewThreadsRequiredToReserveTEBs) {}
	printf("Temp threads confirmed to have been created, returning\n");
}

extern "C" __declspec(dllexport) void releaseReservedTEBs()
{
	// TODO Need to use return codes instead of exceptions?

	for (const auto& tempThreadId : tempThreadIds)
	{
		Util::Thread tempThread(tempThreadId, GetCurrentProcessId());
		// Easier to just kill the thread than having to let it call ExitThread() on its own. We avoid having to wait for all the thread handles to exit.
		tempThread.Terminate(0);
	}
}

extern "C" __declspec(dllexport) void threadWaitAreaEntryPoint()
{
	Util::Thread currentThread(GetCurrentThreadId(), GetCurrentProcessId());
	while (true) currentThread.Suspend(); // Need to loop in case we move execution somewhere else temporarily. Need to ensure we're always suspended while we're in this function
}

extern "C" __declspec(dllexport) DWORD createThreadAtWaitAreaEntryPoint() // TODO Rename this to createWaitingThread
{
	if (!CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&threadWaitAreaEntryPoint, NULL, 0, NULL))
	{
		return 1;
	}

	return 0;
}

// -------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		// TODO Call cleanUp()?
		break;
	}

	return TRUE;
}

HANDLE hCommAreaMapping;
CommArea commArea;
Util::Windows::NativeApi::NtDelayExecution fpNtDelayExecution;

void yieldTimeSlice()
{
	// Same as Sleep(0).
	LARGE_INTEGER delayInterval;
	delayInterval.QuadPart = 0;
	fpNtDelayExecution(0, &delayInterval);
}

void handleCommandWait()
{
	yieldTimeSlice();
}

void* nextBlock;
extern "C" __declspec(dllexport) void* getNextBlockAddr()
{
	return &nextBlock;
}

void* ebpBeforeDispatch;
void* espBeforeDispatch;
void* _ebp;
void* _esp;
void* _eip;
__declspec(naked) void dispatch(const CONTEXT& ctx)
{
	{
		__asm
		{
			// Backup EBP and ESP so we can use this stack later.
			mov [ebpBeforeDispatch], ebp
			mov [espBeforeDispatch], esp

			// Make some space for local variables. No need to clean them up since we've backed up the stack registers already.
			push ebp
			mov ebp, esp
			sub esp, __LOCAL_SIZE
		}

		_ebp = (void*)ctx.Ebp;
		_esp = (void*)ctx.Esp;
		_eip = (void*)ctx.Eip;
		const auto _eflags = ctx.EFlags;
		const auto _edi = ctx.Edi;
		const auto _esi = ctx.Esi;
		const auto _ebx = ctx.Ebx;
		const auto _edx = ctx.Edx;
		const auto _ecx = ctx.Ecx;
		const auto _eax = ctx.Eax;

		// TODO FPU/MMX, SSE, AVX?
		
		// Set context to given CONTEXT structure.
		__asm
		{
			// EFLAGS.
			pushfd
			mov eax, _eflags
			mov[esp], eax
			popfd

			// General purpose registers.
			mov edi, [_edi]
			mov esi, [_esi]
			mov ebx, [_ebx]
			mov edx, [_edx]
			mov ecx, [_ecx]
			mov eax, [_eax]

			mov ebp, [_ebp]
			mov esp, [_esp]
			int3break();
			jmp [_eip]
		}
	}
}

void handleCommandExecuteBlock()
{
	const auto ctx = commArea.ExecuteBlock();
	dispatch(ctx);
}

void commLoop();

extern "C" __declspec(dllexport, naked) void blockFinishedExecuting()
{
	__asm
	{
		// Backup stack registers so we don't have to do arithmetic before saving them in the context structure.
		mov dword ptr ds:[_ebp], ebp // Seems this instruction is acting up, need to be explicit with the size or it'll become a SUB EAX somehow...
		mov [_esp], esp
	}

	__asm
	{
		// Make some space for what's to happen below. Remember we're still on the block's stack.
		push ebp
		mov ebp, esp
		sub esp, __LOCAL_SIZE
	}

	{
		// Backup the context as seen after executing the block. (TODO "as it currently exists" sounds better?)
		CONTEXT ctx;

		__asm
		{
			// General purpose registers.
			mov ctx.Edi, edi
			mov ctx.Esi, esi
			mov ctx.Ebx, ebx
			mov ctx.Edx, edx
			mov ctx.Ecx, ecx
			mov ctx.Eax, eax

			// EBP.
			mov eax, [_ebp]
			mov ctx.Ebp, eax

			// ESP.
			mov eax, [_esp]
			mov ctx.Esp, eax

			// EIP (=next block address).
			mov eax, [nextBlock]
			mov ctx.Eip, eax

			// EFLAGS.
			pushf
			mov eax, [esp]
			mov ctx.EFlags, eax
			popf

			// TODO FPU/MMX, SSE, AVX?
		}

		// Signal that the block finished executing.
		// TODO WARNING! If we suspend instead of sleeping, we may get interrupted after this line and be
		// woken up by MiraiReplayer, even though we're not suspended yet (didn't reach the comm loop yet).
		commArea.ExecuteBlockResponse(ctx);
	}

	__asm
	{
		// Clean up the block's stack.
		mov esp, ebp
		pop ebp
	}

	__asm
	{
		// Restore stack registers from before dispatching to code block.
		mov ebp, [ebpBeforeDispatch]
		mov esp, [espBeforeDispatch]

		// Go back to the comm loop.
		jmp commLoop
	}
}

void (*commandHandlers[CommArea::Commands::NUM_COMMANDS])();

extern "C" __declspec(dllexport) void prepareComm()
{
	// Only need this in MiraiReplayer? Can use NtMapViewOfFileEx from the other process to set up a view in MiraiReplayerDll.
	hCommAreaMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, CommArea::Size, L"CommAreaMapping");
	util_assert(hCommAreaMapping);

	void* commAreaView = MapViewOfFile(hCommAreaMapping, FILE_MAP_ALL_ACCESS, 0, 0, CommArea::Size);
	util_assert(commAreaView);
	commArea.View = commAreaView;

	// Cache the function pointer since we can't retrieve it during comm (can't use the WinAPI).
	fpNtDelayExecution = Util::Windows::NativeApi::GetFpNtDelayExecution();

	// Set up command handlers.
	commandHandlers[CommArea::Commands::WAIT_FOR_COMMAND] = handleCommandWait;
	commandHandlers[CommArea::Commands::EXECUTE_BLOCK] = handleCommandExecuteBlock;
	commandHandlers[CommArea::Commands::EXECUTE_BLOCK_RESPONSE] = handleCommandWait;
}

void cleanUp()
{
	CloseHandle(hCommAreaMapping);
}

void commLoop()
{
	while (true)
	{
		const DWORD command = commArea.GetCommand();

		if (command >= CommArea::Commands::NUM_COMMANDS)
		{
			abort(); // TODO Change to SafeAbort?
		}

		commandHandlers[command]();
	}
}

extern "C" __declspec(dllexport) void startComm()
{
	commLoop();
}