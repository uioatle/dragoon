#include "syscall_handler.h"
#include "recording_handler.h"
#include "event_log_writer.h"

#include "DragoonGlobal\common.h"
#include "DragoonGlobal\new_delete_replacement.h"

#include "lib\Util\include\common.h"
#include "lib\Util\include\process.h"
#include "lib\Util\include\directory.h"
#include "lib\Util\include\native_memory_allocator.h"
#include "lib\Util\include\module.h"
#include "lib\Util\include\lock.h"

#include <cstdio>
#include <iostream>
#include <algorithm>
#include <Windows.h>

// TODO What happens if there's an exception or something that makes us unable to free these pointers? Use smart pointers? It's fine for now, just ignore. As long the recording stops we're good.
static HINSTANCE dragoonDllImageBase;
static Util::SmartHandle* _hProcess; // Don't use directly, use 'process'
static Util::Process* process;
static Util::Module* dragoonDll;
static Util::NativeMemoryAllocator* nativeAllocator;

static bool isRecording = false;

static void SetUpNativeAllocator(const Util::SmartHandle& hProcess)
{
	// If we dynamically allocate the native allocator with malloc comparison with write watch checking is going to notice that bytes in the heap (e.g. internals locks of the native allocator) get updated.
	// This is problematic because that means the whole page is dumped. We can't just ignore this page specifically, because other changes on the same page could be relevant for dumping.
	// We therefore instead allocate some dynamic memory directly using raw syscalls where we can place the native allocator, and we can ignore this memory block when doing comparisons.
	// We also avoid VirtualAlloc and instead use the native API to avoid risking library interaction.
	Util::Windows::NativeApi::NtAllocateVirtualMemory fpNtAllocateVirtualMemory = (Util::Windows::NativeApi::NtAllocateVirtualMemory)Util::Windows::NativeApi::GetNtdllFuncPtr("NtAllocateVirtualMemory");

	void* _baseAddr = NULL;
	SIZE_T _size = sizeof(Util::NativeMemoryAllocator);

	const NTSTATUS status = fpNtAllocateVirtualMemory(hProcess.GetValue(), &_baseAddr, 0, &_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!Util::Windows::IsNtSuccess(status))
	{
		DragoonGlobal::SafeAbort();
	}

	// Use 'placement new' so malloc isn't used, but the memory we allocated with NtAllocateVirtualMemory instead.
	nativeAllocator = new (_baseAddr) Util::NativeMemoryAllocator(hProcess);

	// Override 'new' and 'delete' to use our custom native allocator instead.
	DragoonGlobal::NewDeleteReplacement::SetAllocator(nativeAllocator);
}

static void TerminateNativeAllocator()
{
	// TODO Call VirtualFree or something on nativeAllocator. Can't just use 'delete' since it was allocated with VirtualAlloc (syscall).
	// TODO Should also reset the allocator being used (DragoonGlobal::NewDeleteReplacement::ClearAllocator)?
}

static void ReallocatePrivateMemoryRegionsWithWriteWatchingEnabled()
{
	// Thanks to the "syscall interface hidden memory region" (which possibly is the 64-bit heap) we have to outsource this work to an external process.
	// If we free the aforementioned region (possibly also applies to other similar snowflakes), we'll get access violations and so on since the syscalls we do will try to write to this region.
	// If we instead do this from an external process, this process will be suspended, so no syscalls and therefore no writes will happen that causes this problem.
	PROCESS_INFORMATION procInfo = { 0 };
	STARTUPINFOA startupInfo = { 0 };

	char* cmdLine = (char*)(DragoonGlobal::Paths::releaseDir + "DragoonDllWriteWatchingReallocator.exe" + " " + std::to_string(process->GetId())).c_str();

	// Create the process.
	if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &startupInfo, &procInfo))
	{
		UTIL_THROW_WIN32("CreateProcessA failed");
	}

	// Wait for the process to finish.
	if (WaitForSingleObject(procInfo.hProcess, INFINITE) == WAIT_FAILED)
	{
		UTIL_THROW_WIN32("WaitForSingleObject failed");
	}

	// Make sure the process exited correctly.
	DWORD exitCode;
	if (!GetExitCodeProcess(procInfo.hProcess, &exitCode))
	{
		UTIL_THROW_WIN32("GetExitCodeProcess failed");
	}
	UTIL_ASSERT(exitCode == 0);
}

static void DumpMemorySnapshot()
{
	// To keep things simple, we pretend there is a thread with ID 0.
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms686746(v=vs.85).aspx: "Note that no thread identifier will ever be 0."
	//
	// Using this thread, we dump all memory regions as if they had just been allocated (MemoryRegionAllocatedEvent).
	// The post-processor will recreate the address space from this thread's log and reduce the need for additional complexity specifically for dumping the memory snapshot.
	// AKA It's easier to just dump events and don't add more special code to the replayer than it is to use a custom memory dump routine that must be parsed in a special way.
	Util::ThreadId fakeThreadId = 0;
	Util::Lock dummyMemoryLock;

	// EventLogWriter contains an array that exceeds the stack size, so we need to allocate the object dynamically.
	auto* eventLogWriter = new Dragoon::EventLogWriter(dummyMemoryLock, fakeThreadId);

	dummyMemoryLock.Acquire();
	eventLogWriter->LockForWriting();

	// Find out the span of the current thread's stack memory so we don't dump it.
	const auto pCurrentThreadTeb = Util::Thread(GetCurrentThreadId(), process->GetId()).GetTEB32();
	const void* currentThreadStackStartPage = Util::MemoryRegion(process->GetHandle(), pCurrentThreadTeb->StackLimit, Util::System::PageSize).GetHeader().AllocationBase;
	const void* currentThreadStackStopPage = pCurrentThreadTeb->StackBase;

	const auto isBaseAddrInCurrentThreadStackRange = [&](const void* baseAddr) -> bool
	{
		return baseAddr >= currentThreadStackStartPage && baseAddr < currentThreadStackStopPage;
	};

	// Dump all memory regions.
	for (const auto& memRegionHeader : process->GetMemoryRegionHeaders())
	{
		// TODO What else do we need to skip here? Look at what we skip when adding allocations to the allocation list.

		// Skip free regions.
		if (memRegionHeader.State == MEM_FREE)
		{
			continue;
		}

		// Skip KUSER_SHARED_DATA.
		if (memRegionHeader.AllocationBase == Util::System::KUSER_SHARED_DATA)
		{
			continue;
		}

		// Skip current thread's stack.
		if (isBaseAddrInCurrentThreadStackRange(memRegionHeader.BaseAddress))
		{
			continue;
		}

		// Don't dump DragoonDll.
		if (memRegionHeader.AllocationBase == dragoonDll->GetBaseAddress())
		{
			continue;
		}

		// Skip regions allocated by native allocator.
		if (nativeAllocator->WasAllocationBaseAllocatedByThisAllocator(memRegionHeader.AllocationBase))
		{
			continue;
		}

		if (memRegionHeader.AllocationBase == nativeAllocator)
		{
			continue;
		}
		
		Util::MemoryRegion memRegion(process->GetHandle(), memRegionHeader.BaseAddress, memRegionHeader.RegionSize);

		// TODO Can skip disabling the page guard, because the EventLogWriter should do that automatically (not yet implemented).
		// If the page is guarded, temporarily remove the guard and restore it later.
		const bool regionWasGuarded = memRegion.IsGuarded();
		if (regionWasGuarded)
		{
			memRegion.DisableGuard();
		}

		// Dump memory region as a "memory was allocated" event.
		// TODO Only have to dump committed regions?
		eventLogWriter->AddMemoryRegionAddedEvent(memRegionHeader.BaseAddress, memRegionHeader.AllocationBase, memRegionHeader.RegionSize, memRegionHeader.Protect, memRegionHeader.State);

		// Restore guard protection if it was removed earlier.
		if (regionWasGuarded)
		{
			memRegion.RevertToPreviousProtection();
		}
	}

	// Not strictly necessary.
	eventLogWriter->ReleaseWriteLock();
	dummyMemoryLock.Release();
	eventLogWriter->Flush();

	// Strictly necessary.
	delete eventLogWriter;
}

// Note: If StartRecording() was called to record from the entry point, the main thread will already be suspended,
// so we need to make sure we don't suspend it twice. In the other case it will be -1 and can be ignored.
C_DLLEXPORT DWORD StartRecording(const Util::ThreadId idOfSuspendedMainThread = -1)
{
	try
	{
		std::cout << "In DragoonDll#StartRecording - idOfSuspendedMainThread = " << std::hex << idOfSuspendedMainThread << std::endl;

		const Util::ThreadId currentThreadId = GetCurrentThreadId();

		// Create recording directory.
		Util::Directory::Create(DragoonGlobal::Paths::recordingDir);

		// Retrieve all threads except the current one (it's a temporary thread, we don't want it showing up in the recording logs).
		std::vector<Util::Thread> threads = process->GetThreads();

		threads.erase(std::remove_if(threads.begin(), threads.end(), [&currentThreadId](const Util::Thread& thread)
		{
			return thread.GetId() == currentThreadId;
		}), threads.end());

		// IMPORTANT_TODO What if a new thread APC has already been scheduled and wasn't suspended here? What happens if we get pre-empted in
		// the middle of this function and it ends up being redirected to NewLdrInitializeThunk? Should we use a lock just in case that happens?

		// Suspend all threads so we can do a system snapshot etc. without problems.
		for (auto& thread : threads)
		{
			// Don't suspend main thread twice if already suspended.
			if (thread.GetId() == idOfSuspendedMainThread)
			{
				continue;
			}

			thread.Suspend();
		}

		// We don't want the current thread to be recorded when it exits.
		Dragoon::RecordingHandler::DoNotRecordThreadExit(currentThreadId);

		// Activate event and syscall logging etc. Note that threads have not been resumed yet.
		Dragoon::RecordingHandler::StartRecording(threads, Util::Thread(currentThreadId, process->GetId()));

		// Dumping the current memory snapshot to disk has to be the last thing that is done before resuming
		// the threads, otherwise we'll get an unrecorded zone in between the snapshot and the resume syscalls.
		// We therefore acquire the thread handles first, to ensure they are simple values and won't cause any
		// lookups of any sort when retrieving them. Next we resume the threads with direct syscalls to mitigate
		// the risks of creating said unrecorded zone.
		std::vector<HANDLE> rawThreadHandles;
		for (auto& thread : threads)
		{
			rawThreadHandles.emplace_back(thread.GetHandle().GetValue());
		}

		// Cache the syscall (also to avoid the same potential unrecorded zone).
		const auto fpNtResumeThread = (Util::Windows::NativeApi::NtResumeThread)Util::Windows::NativeApi::GetNtdllFuncPtr("NtResumeThread");

		// Self-explanatory.
		DumpMemorySnapshot();

		// E.T. phone home... (resume all threads)
		for (const auto& rawThreadHandle : rawThreadHandles)
		{
			if (!Util::Windows::IsNtSuccess(fpNtResumeThread(rawThreadHandle, NULL)))
			{
				DragoonGlobal::SafeAbort();
			}
		}

		// We're done.
		isRecording = true;
		Dragoon::SyscallHandler::ResetSyscallCounterSinceRecordingStart();
	}
	catch (const std::exception& e)
	{
		std::cout << "Exception @ DragoonDll#StartRecording: " << e.what() << std::endl; // TODO Log
		return 1;
	}

	return 0;
}

// Reset everything so the recording can start from a clean slate (in the case of multiple recordings).
// This is not the same as terminating the recorder entirely.
NOINLINE void StopRecording()
{
	if (!isRecording)
	{
		return;
	}

	// TODO If called by remote thread, do we have to unregister/hide that thread before we continue?

	// Pretty important.
	Dragoon::RecordingHandler::DisableRecordingOfThread(GetCurrentThreadId());

	// TODO Stop monitoring thread creation: ldrInitializeThunkTrampoline->Disable();

	// Suspend threads.
	std::vector<Util::Thread> threads = process->GetThreads();
	const Util::ThreadId currentThreadId = GetCurrentThreadId();

	for (auto& thread : threads)
	{
		// Don't suspend the current thread or we'll get frozen here.
		if (thread.GetId() != currentThreadId)
		{
			thread.Suspend();
		}
	}

	// Stop recording.
	Dragoon::RecordingHandler::StopRecording(threads);

	// Resume threads.
	for (auto& thread : threads)
	{
		// The current thread was never suspended in the first place.
		if (thread.GetId() != currentThreadId)
		{
			thread.Resume();
		}
	}

	// We're done.
	isRecording = false;
}

C_DLLEXPORT DWORD Init()
{
	try
	{
		Util::Windows::NativeApi::Init();
		Util::Windows::NativeApi::YieldTimeSlice(); // Force-cache whatever syscalls happen in here (YieldTimeSlice() is used e.g. by Util::Lock internally)

		_hProcess = new Util::SmartHandle(GetCurrentProcess(), NULL);

		// Redirect to native memory allocator as early as possible in an attempt to avoid recording probe effect that may cause the replay to fail due to mismatched determinism internally in libraries.
		// Which in English means: Allocate memory, get A. Allocate again from unrecorded zone, get B. Allocate again, get C. During replay, the same steps are performed, but since the unrecorded zone
		// was not recorded, the second allocation never happens. The two allocations now yield A and B instead of A and C, because the standard memory allocator returns the next available memory (B),
		// creating a possibility that the replay may head down the wrong branch at a later time where C was expected but B was given. From that point on every step in the replay will be corrupted.
		//
		// Since the native allocator is only active within the DLL (this one), it is not a problem that we install it early on, because the program will still keep using the standard allocator.
		// It is only the allocation requests that happen within the DLL itself that are redirected to the native allocator. This is pretty obvious since the program we're recording is already compiled and can't magically swap out allocators later.
		// TODO Call DragoonGlobal::ClearAllocator() when freeing the DLL.
		SetUpNativeAllocator(*_hProcess);

		DragoonGlobal::Logging::Init();

		process = new Util::Process(*_hProcess, GetCurrentProcessId());

		dragoonDll = new Util::Module(process->GetHandle(), dragoonDllImageBase);

		// This step must be done before initializing the syscall handler if you don't want GetWriteWatch to fail (since the regions aren't write watched).
		ReallocatePrivateMemoryRegionsWithWriteWatchingEnabled();

		Dragoon::RecordingHandler::Init(process, dragoonDll, nativeAllocator);
	}
	catch (const std::exception& e)
	{
		std::cout << "Exception @ DragoonDll#Init: " << e.what() << std::endl; // TODO Log
		return 1;
	}

	return 0;
}

/* DLL Notifications */
// TODO We won't be using some of these in the final version since Dragoon will have been removed from the PEB's DLL list (most likely).
// By then these will have been replaced by hooks in the appropriate locations.

void OnDllProcessAttach(const HINSTANCE hinstDLL)
{
	std::cout << "In DragoonDll#DllMain" << std::endl;
	dragoonDllImageBase = hinstDLL;
	// Not calling Init() in here since it's strongly recommended to not do anything heavy in DllMain (google DllMain deadlock to see what I mean). The function should be called manually later.
}

void OnDllThreadAttach()
{
	// Note:
	// Not doing OnThreadStart here, because we won't have captured the address space changes from LdrInitializeThunk to where we are now,
	// which means the recording won't be deterministic and we can't replay properly (it's an unrecorded zone). We're hooking LdrInitializeThunk in StartRecording instead.
}

void OnDllThreadDetach()
{
	if (isRecording)
	{
		// TODO?
		//recorder->OnThreadExit(GetCurrentThreadId());
	}
}

void OnDllProcessDetach()
{
	__asm int 3;

	// TODO Do we need to ensure only one thread is in here? It's the process detach function, not thread detach, but still? Any chance of problems? In that case, use a lock?

	StopRecording();

	Dragoon::RecordingHandler::Terminate();
	DragoonGlobal::Logging::Terminate();

	//TerminateNativeAllocator();

	delete process;
	delete _hProcess;

	__asm int 3;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		OnDllProcessAttach(hinstDLL);
		break;
	case DLL_THREAD_ATTACH:
		OnDllThreadAttach();
		break;
	case DLL_THREAD_DETACH:
		OnDllThreadDetach();
		break;
	case DLL_PROCESS_DETACH:
		OnDllProcessDetach();
		break;
	}

	return TRUE;
}