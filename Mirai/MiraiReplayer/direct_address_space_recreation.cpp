#include "direct_address_space_recreation.h"

#include "common.h"
#include "windefs.h"
#include "system.h"
#include "smart_handle.h"
#include "thread.h"
#include "memory_region.h"
#include "module.h"

#include <cassert>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <set>
#include <map>
#include <exception>
#include <memory>
#include <algorithm>
#include <functional>
#include <Windows.h>

PROCESS_INFORMATION spawnReplayProcess(void)
{
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	ZeroMemory(&processInfo, sizeof(processInfo));
	startupInfo.cb = sizeof(startupInfo);

	// Not starting it in a suspended state since the PEB won't be initialized yet, so we won't be able to attach (http://hooked-on-mnemonics.blogspot.no/2013/01/debugging-hollow-processes.html).
	if (!CreateProcess(L"C:\\Code\\Projects\\Mirai\\Release\\MiraiReplayProcess.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo))
	{
		throw std::exception("Failed to spawn replay process");
	}

	return processInfo;
}

const char* replayerDllPath = "C:\\Code\\Projects\\Mirai\\Release\\MiraiReplayerDll.dll";

void* getFuncOffsetInDll(const std::string& dllPath, const std::string& funcName)
{
	const HMODULE hLibrary = LoadLibraryA(dllPath.c_str());
	if (!hLibrary) throw std::exception("LoadLibraryA failed");

	const FARPROC funcAddr = GetProcAddress(hLibrary, funcName.c_str());
	if (!funcAddr) throw std::exception("GetProcAddress failed");

	void* funcOffset = (void*)((DWORD)funcAddr - (DWORD)hLibrary);

	if (!FreeLibrary(hLibrary)) throw std::exception("FreeLibrary failed");

	return funcOffset;
}

bool memRegionHeaderListContainsAllocationBase(const std::vector<MEMORY_BASIC_INFORMATION>& memRegionHeaders, LPCVOID allocationBase)
{
	for (const auto& memRegionHeader : memRegionHeaders)
	{
		if (memRegionHeader.AllocationBase == allocationBase)
		{
			return true;
		}
	}

	return false;
}

std::vector<MEMORY_BASIC_INFORMATION> unmapSections(
	const Util::SmartHandle& hProcess,
	const std::vector<MEMORY_BASIC_INFORMATION>& memRegionHeaders,
	const std::vector<MEMORY_BASIC_INFORMATION>& memRegionHeadersToBeSkipped
	)
{
	const auto fpNtUnmapViewOfSection = Util::Windows::NativeApi::GetFpNtUnmapViewOfSection();
	util_assert(fpNtUnmapViewOfSection);

	std::vector<MEMORY_BASIC_INFORMATION> unmappableSections;
	std::set<void*> unmappedAllocationBases;

	for (const auto& memRegionHeader : memRegionHeaders)
	{
		// Not a memory mapped section?
		if (memRegionHeader.Type != MEM_MAPPED)
		{
			continue;
		}

		// Did we already unmap a section with this allocation base?
		if (unmappedAllocationBases.find(memRegionHeader.AllocationBase) != unmappedAllocationBases.end())
		{
			continue;
		}

		// Should we skip this region?
		if (memRegionHeaderListContainsAllocationBase(memRegionHeadersToBeSkipped, memRegionHeader.AllocationBase))
		{
			continue;
		}

		// Perform the unmapping.
		const auto status = fpNtUnmapViewOfSection(hProcess.GetValue(), memRegionHeader.AllocationBase);

		if (status == ERROR_SUCCESS)
		{
			unmappedAllocationBases.insert(memRegionHeader.AllocationBase);
		}
		else
		{
			unmappableSections.push_back(memRegionHeader);
		}
	}

	return unmappableSections;
}

std::vector<MEMORY_BASIC_INFORMATION> unmapImages(
	const Util::SmartHandle& hProcess,
	const std::vector<MEMORY_BASIC_INFORMATION>& memRegionHeaders,
	const std::vector<MEMORY_BASIC_INFORMATION>& memRegionHeadersToBeSkipped
)
{
	const auto fpNtUnmapViewOfSection = Util::Windows::NativeApi::GetFpNtUnmapViewOfSection();
	util_assert(fpNtUnmapViewOfSection);

	std::vector<MEMORY_BASIC_INFORMATION> unmappableImages;
	std::set<void*> unmappedAllocationBases;

	for (const auto& memRegionHeader : memRegionHeaders)
	{
		// Section isn't a mapped image?
		if (memRegionHeader.Type != MEM_IMAGE)
		{
			continue;
		}

		// Did we already unmap a section with this allocation base?
		if (unmappedAllocationBases.find(memRegionHeader.AllocationBase) != unmappedAllocationBases.end())
		{
			continue;
		}

		// Should we skip this region?
		if (memRegionHeaderListContainsAllocationBase(memRegionHeadersToBeSkipped, memRegionHeader.AllocationBase))
		{
			continue;
		}

		// Do the unmapping.
		auto status = fpNtUnmapViewOfSection(hProcess.GetValue(), memRegionHeader.AllocationBase);

		if (status == ERROR_SUCCESS)
		{
			unmappedAllocationBases.insert(memRegionHeader.AllocationBase);
		}
		else
		{
			unmappableImages.push_back(memRegionHeader);
		}
	}

	return unmappableImages;
}

std::vector<MEMORY_BASIC_INFORMATION> freePrivateMemRegions(
	const Util::SmartHandle& hProcess,
	const std::vector<MEMORY_BASIC_INFORMATION>& memRegionHeaders,
	const std::vector<MEMORY_BASIC_INFORMATION>& memRegionHeadersToBeSkipped
)
{
	const auto fpNtFreeVirtualMemory = Util::Windows::NativeApi::GetFpNtFreeVirtualMemory();
	util_assert(fpNtFreeVirtualMemory);

	std::vector<MEMORY_BASIC_INFORMATION> unfreeableMemRegions;
	std::set<void*> freedAllocationBases;

	for (const auto& memRegionHeader : memRegionHeaders) {
		// Not a private memory region?
		if (memRegionHeader.Type != MEM_PRIVATE) {
			continue;
		}

		// Did we already free this allocation base?
		if (freedAllocationBases.find(memRegionHeader.AllocationBase) != freedAllocationBases.end()) {
			continue;
		}

		// Should we skip this region?
		if (memRegionHeaderListContainsAllocationBase(memRegionHeadersToBeSkipped, memRegionHeader.AllocationBase))
		{
			continue;
		}

		if (memRegionHeader.AllocationBase == Util::System::KUSER_SHARED_DATA)
		{
			continue;
		}

		// We'll clear this later manually.
		if (memRegionHeader.AllocationBase == Util::System::PEB_Base)
		{
			continue;
		}

		// TODO?
		//disablePageGuard(memRegionHeader);

		if (!VirtualFreeEx(hProcess.GetValue(), memRegionHeader.AllocationBase, 0, MEM_RELEASE))
		{
			unfreeableMemRegions.push_back(memRegionHeader);
		}

		// We note this allocation base regardless of whether we succeeded or not.
		// For failed attempts there's no point trying to do it with another call with another base address (but same allocation base).
		// TODO Change this for the other two functions?
		freedAllocationBases.insert(memRegionHeader.AllocationBase);
	}

	return unfreeableMemRegions;
}

std::vector<MEMORY_BASIC_INFORMATION> getRecordedMemRegionHeadersToReserve(const std::vector<std::shared_ptr<RecordedMemoryRegion>>& recordedMemRegions)
{
	std::vector<MEMORY_BASIC_INFORMATION> headersToReserve;

	// TODO This function should return (most of this is already done, just read between the lines):
	// TODO - Future allocations from the syscall log
	// TODO - All private regions
	// TODO - Views
	// TODO - Modules
	// TODO - TEBs (at least those that aren't in system-only-accessible areas)
	// TODO - Thread stacks
	// TODO - Other thread regions
	// TODO - PEB (it's only accessible by system, so no point?)
	// TODO - etc.

	for (const auto& recordedMemRegion : recordedMemRegions)
	{
		headersToReserve.push_back(recordedMemRegion->header);
	}

	return headersToReserve;
}

std::vector<LPCVOID> reserveRecordedMemoryRegions(
	const Util::SmartHandle& hReplayProcess,
	const std::vector<MEMORY_BASIC_INFORMATION>& recordedMemRegionHeadersToReserve
)
{
	// Move recorded memory regions into lists where each region in the list share the same allocation base.
	// TODO Should be using references, there's too much copying here.
	std::set<LPCVOID> allocationBases;
	for (const auto& header : recordedMemRegionHeadersToReserve) allocationBases.insert(header.AllocationBase);

	std::vector<std::vector<MEMORY_BASIC_INFORMATION>> headersSharingAllocationBases;
	for (const auto& allocationBase : allocationBases)
	{
		std::vector<MEMORY_BASIC_INFORMATION> matches;
		for (const auto& header : recordedMemRegionHeadersToReserve)
		{
			if (header.AllocationBase == allocationBase)
			{
				matches.push_back(header);
			}
		}
		headersSharingAllocationBases.push_back(matches);
	}

	std::vector<LPCVOID> successfulReservations;

	for (const auto& headersSharingAllocationBase : headersSharingAllocationBases)
	{
		const auto allocationBase = headersSharingAllocationBase[0].AllocationBase;

		// Need to merge reserve and commit sizes here or we end up with a race condition since there will be holes.
		// Still need to reserve the regions in sizes of the allocation granularity, though, since there will already
		// exist memory here and there and we want to reserve in between that, not demand to take those regions as well.
		uint32_t sumOfAllRegionSizes = 0;
		for (const auto& header : headersSharingAllocationBase) sumOfAllRegionSizes += header.RegionSize;

		// Note that if the size is something like 0x2A000 that's overlapping by 0xA000,
		// so we'll need 2 * 0x10000 blocks + another for that overlapping 0xA000.
		const auto numAllocationsToMake = (sumOfAllRegionSizes / Util::System::AllocationGranularitySize) + (sumOfAllRegionSizes % Util::System::AllocationGranularitySize == 0 ? 0 : 1);

		for (uint32_t i = 0; i < numAllocationsToMake; i++)
		{
			void* baseAddress = (unsigned char*)allocationBase + (i * Util::System::AllocationGranularitySize);

			Util::MemoryRegion memRegion(hReplayProcess, baseAddress, Util::System::AllocationGranularitySize);

			if (memRegion.IsFree())
			{
				memRegion.Allocate(MEM_RESERVE, PAGE_NOACCESS);
				successfulReservations.push_back(baseAddress); // Note: Not allocation base!
			}
		}
	}

	return successfulReservations;
}

LPCVOID getAddrOfFuncInInjectedReplayerDll(LPCVOID injectedReplayerDllBaseAddr, const std::string& funcName)
{
	return (LPCVOID)((DWORD)injectedReplayerDllBaseAddr + (DWORD)getFuncOffsetInDll(replayerDllPath, funcName));
}

void createThreadAtMiraiReplayerDllThreadWaitAreaEntryPoint(const Util::SmartHandle& hReplayProcess, LPCVOID injectedReplayerDllBaseAddr)
{
	// Resolve function addresses in the injected DLL.
	LPCVOID reserveTEBsTemporarilyAddr = getAddrOfFuncInInjectedReplayerDll(injectedReplayerDllBaseAddr, "reserveTEBsTemporarily");
	LPCVOID releaseReservedTEBsAddr = getAddrOfFuncInInjectedReplayerDll(injectedReplayerDllBaseAddr, "releaseReservedTEBs");
	LPCVOID createThreadAtWaitAreaEntryPointAddr = getAddrOfFuncInInjectedReplayerDll(injectedReplayerDllBaseAddr, "createThreadAtWaitAreaEntryPoint");

	HANDLE hThread;

	// Reserve TEBs required for the recording, but only temporarily while we create the thread for MiraiReplayerDll.
	// We don't want the WaitingThread to take up one of the recorded TEB slots.
	if (!(hThread = CreateRemoteThread(hReplayProcess.GetValue(), NULL, 0, (LPTHREAD_START_ROUTINE)reserveTEBsTemporarilyAddr, NULL, 0, NULL)))
	{
		Util::ThrowExceptionWithWin32ErrorCode("CreateRemoteThread failed");
	}

	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) Util::ThrowExceptionWithWin32ErrorCode("WaitForSingleObject failed");

	// Create the remote thread (the Waiting Thread).
	// IMPORTANT! Apparently we can't just start a remote thread at MiraiReplayerDll#threadWaitAreaEntryPoint directly, because it seems
	// that due to the fact it was created with CreateRemoteThread instead of CreateThread the TEB won't get allocated along with all the
	// others (a few pages below the previous TEB which would be normal), and the TEB will instead get allocated at a high address
	// such as 0x7EFDA000 (0x7EFD8000 in memory view, aka TEB64). This appears to be the second available TEB or so, so it'll cause problems
	// when recreating the recorded TEBs. To get around this we simply create the remote thread on a function that calls CreateThread
	// internally instead on the threadWaitAreaEntryPoint.
	// 
	// Author's note: I don't remember exactly what this comment is trying to convey but it has something to do with being unable to
	// use CreateRemoteThread because the TEB that is allocated doesn't get allocated where one would expect, following the usual pattern.
	// We therefore need to use CreateThread instead which doesn't have this problem. Not sure why this is a problem, though, but I think
	// it's because we reserve TEBs in the CreateRemoteThread call before this one, and there may be a "hole" that CreateRemoteThread
	// uses even though we'd expect the TEB to be allocated further down. E.g., if we allocate 100 threads we expect 100 TEBs, then this
	// new thread should get TEB number 101, but instead it takes TEB number 2, because there happened to be an empty slot there for some
	// reason. Sorry, it's so long since I wrote this. I have a feeling this might not be a problem and was just a coincidence that I was
	// too inexperienced to deal with back then as I've frequently seen the first TEB get address 0x7EFD8000 or 0x7EFDB000, so maybe I was
	// wrong and it's not a problem. Either way, only experimentation can tell.
	if (!(hThread = CreateRemoteThread(hReplayProcess.GetValue(), NULL, 0, (LPTHREAD_START_ROUTINE)createThreadAtWaitAreaEntryPointAddr, NULL, 0, NULL)))
	{
		Util::ThrowExceptionWithWin32ErrorCode("Failed to create remote thread at MiraiReplayerDll#createThreadAtWaitAreaEntryPoint");
	}

	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) Util::ThrowExceptionWithWin32ErrorCode("WaitForSingleObject failed");

	DWORD threadExitCode;
	GetExitCodeThread(hThread, &threadExitCode);
	if (threadExitCode > 0) throw std::exception("MiraiReplayerDll#createThreadAtWaitAreaEntryPoint returned exit code that was not 'success'");

	// Release the temporary TEBs.
	if (!(hThread = CreateRemoteThread(hReplayProcess.GetValue(), NULL, 0, (LPTHREAD_START_ROUTINE)releaseReservedTEBsAddr, NULL, 0, NULL)))
	{
		Util::ThrowExceptionWithWin32ErrorCode("CreateRemoteThread failed");
	}

	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) Util::ThrowExceptionWithWin32ErrorCode("WaitForSingleObject failed");

	// TODO Close hThread
}

void releaseReservedRecordedMemRegions(
	const Util::SmartHandle& hReplayProcess,
	const std::vector<LPCVOID>& successfullyReservedBaseAddresses
)
{
	for (const auto& successfullyReservedBaseAddress : successfullyReservedBaseAddresses)
	{
		Util::MemoryRegion::Free(hReplayProcess, successfullyReservedBaseAddress);
	}
}

std::vector<MEMORY_BASIC_INFORMATION> getAddedMemRegions(
	const std::vector<MEMORY_BASIC_INFORMATION>& oldMemRegions,
	const std::vector<MEMORY_BASIC_INFORMATION>& newMemRegions
)
{
	std::vector<MEMORY_BASIC_INFORMATION> addedMemRegions;

	for (const auto& newMemRegion : newMemRegions)
	{
		bool isOldMemRegion = false;

		for (const auto& oldMemRegion : oldMemRegions)
		{
			if (newMemRegion.AllocationBase == oldMemRegion.AllocationBase)
			{
				isOldMemRegion = true;
				break;
			}
		}

		if (isOldMemRegion)
		{
			continue;
		}

		addedMemRegions.push_back(newMemRegion);
	}

	return addedMemRegions;
}

void clearAddressSpace(
	const Util::SmartHandle& hProcess,
	const Util::ProcessId processId,
	const std::vector<MEMORY_BASIC_INFORMATION>& memRegionHeadersToSkip
)
{
	const auto replayProcessMemRegionHeaders = Util::System::GetMemoryRegionHeaders(processId);

	// Unmap images.
	// Doing this first just in case image depends on either a mapped view or private memory (which could crash the module if it was executing, which it isn't...).
	const auto imagesNotUnmapped = unmapImages(hProcess, replayProcessMemRegionHeaders, memRegionHeadersToSkip);

	if (imagesNotUnmapped.size() > 0)
	{
		printf("Images not unmapped:\n");
		for (const auto& imageNotUnmapped : imagesNotUnmapped) Util::PrintMemoryRegionHeader(imageNotUnmapped);
		throw std::exception("Shouldn't be here?");
	}

	// Unmap sections.
	const auto sectionsNotUnmapped = unmapSections(hProcess, replayProcessMemRegionHeaders, memRegionHeadersToSkip);

	if (sectionsNotUnmapped.size() > 0)
	{
		printf("Sections not unmapped:\n");
		for (const auto& sectionNotUnmapped : sectionsNotUnmapped) Util::PrintMemoryRegionHeader(sectionNotUnmapped);
		throw std::exception("Shouldn't be here?");
	}

	// Free private memory regions.
	const auto privateMemRegionsNotFreed = freePrivateMemRegions(hProcess, replayProcessMemRegionHeaders, memRegionHeadersToSkip);

	if (privateMemRegionsNotFreed.size() > 0)
	{
		printf("Private memory regions not freed:\n");
		for (const auto& privateMemRegionNotFreed : privateMemRegionsNotFreed) Util::PrintMemoryRegionHeader(privateMemRegionNotFreed);
		throw std::exception("Shouldn't be here?");
	}
}

DWORD convertMappedViewProtectionToPrivateRegionProtection(const DWORD mappedViewProtection)
{
	switch (mappedViewProtection)
	{
	case PAGE_EXECUTE_WRITECOPY:
		return PAGE_EXECUTE_READWRITE;
	case PAGE_WRITECOPY:
		return PAGE_READWRITE;
	default:
		return mappedViewProtection;
	}
}

void recreateReservations(
	const Util::SmartHandle& hProcess,
	const std::vector<std::shared_ptr<RecordedMemoryRegion>>& recordedMemRegions
)
{
	// Move recorded memory regions into lists where each region in the list share the same allocation base.
	// TODO Should be using references, there's too much copying here.
	std::set<LPCVOID> allocationBases;
	for (const auto& recordedMemRegion : recordedMemRegions) allocationBases.insert(recordedMemRegion->header.AllocationBase);

	std::vector<std::vector<std::shared_ptr<RecordedMemoryRegion>>> recordedMemRegionsSharingAllocationBases;
	for (const auto& allocationBase : allocationBases)
	{
		std::vector<std::shared_ptr<RecordedMemoryRegion>> matches;
		for (const auto& recordedMemRegion : recordedMemRegions)
		{
			if (recordedMemRegion->header.AllocationBase == allocationBase)
			{
				matches.push_back(recordedMemRegion);
			}
		}
		recordedMemRegionsSharingAllocationBases.push_back(matches);
	}

	// For each allocation base, reserve an allocation big enough to hold all the regions for that allocation base (whether reserved or committed).
	// Note: Actually have to reserve one big block with all reservations and commits included in it,
	// because VirtualAlloc with MEM_RESERVE rounds down to allocation granularity, so if you try to reserve two different regions
	// they'll both reserve the same base address and overlap. So basically you should think of one allocation boundary as one "unit",
	// in which you reserve only once what you need.
	printf("Reserving memory regions (including commit sizes, that is, RESERVE-COMMIT-RESERVE, it reserves all three as one big block, not just the RESERVE ones):\n");
	for (const auto& recordedMemRegionsSharingAllocationBase : recordedMemRegionsSharingAllocationBases)
	{
		const auto allocationBase = recordedMemRegionsSharingAllocationBase[0]->header.AllocationBase;

		// TODO Need to do something about this, or?
		if (allocationBase == Util::System::Unknown_Base)
		{
			continue;
		}

		// Count the total size.
		DWORD totalReservedSize = 0;
		for (const auto& memRegion : recordedMemRegionsSharingAllocationBase) totalReservedSize += memRegion->header.RegionSize;

		printf("Allocation base: %p\n", allocationBase);
		for (const auto& memRegion : recordedMemRegionsSharingAllocationBase) Util::PrintMemoryRegionHeader(memRegion->header);

		// Reserve that size.
		// Can't use header.AllocationProtect for initial protections, in case we get PAGE_EXECUTE_WRITECOPY or PAGE_WRITECOPY,
		// which are not supported by VirtualAlloc*. That's why we use PAGE_EXECUTE_READWRITE instead.
		// Source: http://waleedassar.blogspot.no/2012/09/pageexecutewritecopy-as-anti-debug-trick.html
		// Author's note: Not sure how relevant this is anymore, but the comment seemed to fit best here.
		Util::MemoryRegion memRegion(hProcess, allocationBase, totalReservedSize);
		memRegion.Allocate(MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
}

void recreateCommits(
	const Util::SmartHandle& hProcess,
	const std::vector<std::shared_ptr<RecordedMemoryRegion>>& recordedMemRegions
)
{
	printf("Committing memory regions:\n");
	for (const auto& recordedMemRegion : recordedMemRegions)
	{
		// Obviously want nothing to do with reserved regions at this point, we're just here to commit and fill the pages.
		if (recordedMemRegion->header.State != MEM_COMMIT)
		{
			continue;
		}

		Util::PrintMemoryRegionHeader(recordedMemRegion->header);

		Util::MemoryRegion memRegion(hProcess, recordedMemRegion->header.BaseAddress, recordedMemRegion->header.RegionSize);
		memRegion.Allocate(MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (recordedMemRegion->containsData())
		{
			// Write the data to the region before changing the protection to ensure we have write permission.
			memRegion.WriteData(recordedMemRegion->data.get(), recordedMemRegion->dataSize);
		}

		// Not all recorded regions used to be private regions (may have been mapped views),
		// and they may have file mapping protections that aren't valid as a private region, so we need to replace
		// the protection for those cases.
		// TODO https://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx says something about
		// DEP for the WRITECOPY protections. Do we have to handle something related to this for our new private regions here?
		memRegion.ChangeProtection(convertMappedViewProtectionToPrivateRegionProtection(recordedMemRegion->header.Protect));
	}
}

void recreateTebs(const Util::SmartHandle& hProcess, const std::vector<std::shared_ptr<RecordedMemoryRegion>>& recordedTebRegions)
{
	printf("Recreating TEBs:\n");
	for (const auto& recordedTebRegion : recordedTebRegions)
	{
		Util::PrintMemoryRegionHeader(recordedTebRegion->header);

		if (!recordedTebRegion->containsData())
		{
			throw std::exception("Recorded TEB memory region does not contain any data");
		}

		Util::MemoryRegion tebRegion(hProcess, recordedTebRegion->header.BaseAddress, recordedTebRegion->header.RegionSize);
		tebRegion.WriteData(recordedTebRegion->data.get(), recordedTebRegion->dataSize);
	}
}

void recreatePeb(const Util::SmartHandle& hProcess, const std::shared_ptr<RecordedMemoryRegion>& recordedPebRegion)
{
	printf("Recreating PEB:\n");
	Util::PrintMemoryRegionHeader(recordedPebRegion->header);

	if (!recordedPebRegion->containsData())
	{
		throw std::exception("Recorded PEB memory region does not contain any data");
	}

	Util::MemoryRegion pebRegion(hProcess, recordedPebRegion->header.BaseAddress, recordedPebRegion->header.RegionSize);
	pebRegion.WriteData(recordedPebRegion->data.get(), recordedPebRegion->dataSize);
}

void recreateAddressSpaceFromRecording(
	const Util::SmartHandle& hProcess,
	const std::vector<std::shared_ptr<RecordedMemoryRegion>>& recordedMemRegions,
	const std::vector<std::shared_ptr<RecordedMemoryRegion>>& recordedTebRegions,
	const std::shared_ptr<RecordedMemoryRegion>& recordedPebRegion
)
{
	recreateReservations(hProcess, recordedMemRegions);
	recreateCommits(hProcess, recordedMemRegions);

	// No need to change protection for these, since they're always PAGE_READWRITE, both initial and current.
	recreateTebs(hProcess, recordedTebRegions);
	recreatePeb(hProcess, recordedPebRegion);
}

std::set<Util::ThreadId> createThreadsInReplayProcessWithTEBs(
	const Util::SmartHandle& hReplayProcess,
	const Util::ProcessId replayProcessId,
	const std::vector<LPCVOID>& recordedThreadTEBAddrs,
	const void* injectedReplayerDllBaseAddr,
	Util::Thread& waitingThread
)
{
	// Verify none of the TEBs we're trying to reserve have already been reserved by other threads.
	for (auto& thread : Util::System::GetThreads(replayProcessId))
	{
		const void* threadTeb32Addr = thread.GetTEBBaseAddr();

		for (const auto& recordedThreadTEBAddr : recordedThreadTEBAddrs)
		{
			if (((char*)recordedThreadTEBAddr + Util::System::TEB32_Offset) == threadTeb32Addr)
			{
				std::stringstream errorMsg;
				errorMsg << std::hex << "TEB32 " << threadTeb32Addr << " in list already taken by thread ID " << thread.GetId() << ". As such it can't be reserved by a temp thread";
				throw std::exception(errorMsg.str().c_str());
			}
		}
	}

	// Convert the TEBs to their TEB32 format, since that's what we're after.
	std::vector<LPCVOID> recordedThreadTEB32Addrs = recordedThreadTEBAddrs;
	std::transform(recordedThreadTEB32Addrs.begin(), recordedThreadTEB32Addrs.end(), recordedThreadTEB32Addrs.begin(), [](LPCVOID elem)
	{
		return (char*)elem + Util::System::TEB32_Offset;
	});

	// Get the address of MiraiReplayerDll#systemReservedAllocationBases. It's an empty array we'll fill with the "set" above.
	LPCVOID threadEntryPointAddr = getAddrOfFuncInInjectedReplayerDll(injectedReplayerDllBaseAddr, "getSystemReservedAllocationBasesArrayAddr");
	const void* replayerDllSystemReservedAllocationBasesAddr = (void*)Util::Thread::CreateRemote(hReplayProcess, replayProcessId, threadEntryPointAddr, NULL).GetExitCode();

	// Write the "set" to the target process at a statically allocated area within the DLL.
	Util::MemoryRegion memRegion(hReplayProcess, (void*)replayerDllSystemReservedAllocationBasesAddr, sizeof(LPCVOID)* 1024); // TODO Un-hardcode the size
	memRegion.WriteData(recordedThreadTEB32Addrs.data(), sizeof(LPCVOID)* recordedThreadTEB32Addrs.size());

	// Now that we've passed over the data to the replayer process, call a function to process the data.
	LPCVOID createThreadsWithTEBsAddr = getAddrOfFuncInInjectedReplayerDll(injectedReplayerDllBaseAddr, "createThreadsWithTEBs");

	// Need to use the waiting thread since it already has a TEB far away from those we are trying to reserve,
	// so it won't interfere like CreateRemoteThread() would (a new remote thread would take up a TEB slot etc.).
	// Move the waiting thread over to createThreadsWithTEBsAddr() to indirectly call the function.
	const void* newEip = createThreadsWithTEBsAddr;
	const void* oldEip = waitingThread.ChangeEip(newEip);

	// The thread is already suspended, in a free waiting state, so it's safe to force a resume here as
	// there's nothing waiting to resume it later.
	waitingThread.ForceResume();

	// Wait for the function call to end.
	Sleep(1000); // TODO Don't use Sleep, wait for the function to return instead

	// Bring the thread back to the waiting area.
	// WARNING! The function we swapped to earlier actually calls threadWaitAreaEntryPoint() internally,
	// because otherwise it'll return (ASM: ret) back to where, exactly?
	// It's easier to just call the wait entry point and then later move EIP there (not that we would have to since it's already there...).
	// Just keep this in mind when rewriting, it has to be done properly next time.
	waitingThread.ChangeEip(oldEip);

	// Get address of the function's result buffer.
	LPCVOID getCreateThreadsWithTEBsResultsArrayAddrAddr = getAddrOfFuncInInjectedReplayerDll(injectedReplayerDllBaseAddr, "getCreateThreadsWithTEBsResultsArrayAddr");
	const void* createThreadsWithTEBsResultsArrayAddr = (void*)Util::Thread::CreateRemote(hReplayProcess, replayProcessId, getCreateThreadsWithTEBsResultsArrayAddrAddr, NULL).GetExitCode();

	// Read the results from the result buffer.
	Util::ThreadId createThreadsWithTEBsResults[1024];
	Util::MemoryRegion createThreadsWithTEBsResultsMemRegion(hReplayProcess, (void*)createThreadsWithTEBsResultsArrayAddr, sizeof(Util::ThreadId) * 1024); // TODO Un-hardcode the size
	createThreadsWithTEBsResultsMemRegion.ReadData(&createThreadsWithTEBsResults, sizeof(createThreadsWithTEBsResults)); // TODO Un-hardcode number of bytes to read

	// Process the results.
	const Util::ThreadId* pCreateThreadsWithTEBsResults = createThreadsWithTEBsResults;
	DWORD resultArraySize = 0;

	std::set<Util::ThreadId> idsOfTempThreadsOwningTebs;

	while (*pCreateThreadsWithTEBsResults)
	{
		resultArraySize++;
		const Util::ThreadId resultThreadId = *pCreateThreadsWithTEBsResults++;
		idsOfTempThreadsOwningTebs.insert(resultThreadId);

		printf("Temp thread ID: %08X\n", resultThreadId);
	}

	printf("Array size: %u\n", resultArraySize);
	if (resultArraySize == 0)
	{
		pCreateThreadsWithTEBsResults = createThreadsWithTEBsResults;
		printf("createThreadsWithTEBs() failed with error code %u\n", pCreateThreadsWithTEBsResults[1]);
		throw std::exception("createThreadsWithTEBs() failed. See last printf() for details");
	}

	return idsOfTempThreadsOwningTebs;
}

void verifyAddressSpaceWasCleared(
	const std::vector<MEMORY_BASIC_INFORMATION>& replayProcessMemStateBeforeDoingAnything,
	const std::vector<MEMORY_BASIC_INFORMATION>& currentMemRegions,
	const std::vector<LPCVOID>& memRegionBaseAddrsToSkip
)
{
	printf("\nMemory regions before doing anything:\n");
	for (const auto& memRegion : replayProcessMemStateBeforeDoingAnything) Util::PrintMemoryRegionHeader(memRegion);

	printf("\nCurrent memory regions:\n");
	for (const auto& memRegion : currentMemRegions) Util::PrintMemoryRegionHeader(memRegion);

	for (const auto& oldMemRegion : replayProcessMemStateBeforeDoingAnything)
	{
		// Skip this memory region base address?
		if (std::find(memRegionBaseAddrsToSkip.begin(), memRegionBaseAddrsToSkip.end(), oldMemRegion.BaseAddress) != memRegionBaseAddrsToSkip.end())
		{
			continue;
		}

		// Check if the old memory region still exists and if the headers are equal (since another region may have taken its place).
		for (const auto& currentMemRegion : currentMemRegions)
		{
			DWORD numMatchingBytes = 0;

			for (int i = 0; i < sizeof(MEMORY_BASIC_INFORMATION); i++)
			{
				if (((unsigned char*)&oldMemRegion)[i] == ((unsigned char*)&currentMemRegion)[i])
				{
					numMatchingBytes++;
				}
			}

			// All bytes matching?
			if (numMatchingBytes == sizeof(MEMORY_BASIC_INFORMATION))
			{
				printf("Old memory region exists when it shouldn't:\n");
				Util::PrintMemoryRegionHeader(oldMemRegion);
				throw std::exception("See last printf()");
			}
		}
	}
}

void verifyAddressSpaceMemoryRegionHeadersMatchRecording(
	const Util::SmartHandle& hReplayProcess,
	const std::vector<std::shared_ptr<RecordedMemoryRegion>>& recordedMemRegions,
	const std::vector<MEMORY_BASIC_INFORMATION>& addedMemRegionHeaders,
	const std::vector<LPCVOID>& recordedThreadTEBAddrs
)
{
	// Make a copy so we don't mess up anything in case something else needs the original.
	// TODO ???
	auto addedMemRegionHeadersCopy = addedMemRegionHeaders;

	// TEBs that were added to the address space (reserved-to-be-filled, rather) shouldn't be considered "added",
	// because then we'll ignore them when we really want to verify they match the recording.
	// To fix this we remove them from the "added" list.
	addedMemRegionHeadersCopy.erase(std::remove_if(addedMemRegionHeadersCopy.begin(), addedMemRegionHeadersCopy.end(), [&](const MEMORY_BASIC_INFORMATION& memRegion)
	{
		return std::find(recordedThreadTEBAddrs.begin(), recordedThreadTEBAddrs.end(), memRegion.AllocationBase) != recordedThreadTEBAddrs.end();
	}), addedMemRegionHeadersCopy.end());

	/************************************************************/
	// Retrieve the current memory regions, or rather, the recreated memory regions.
	auto currentMemRegionHeaders = Util::System::GetMemoryRegionHeaders(GetProcessId(hReplayProcess.GetValue()));

	// Remove free regions or regions we added ourselves (injected DLL, thread stacks etc.),
	// excluding TEBs since we want to match those in the recreated address space.
	const auto removalPredicate = [&](const MEMORY_BASIC_INFORMATION& memRegionHeader)
	{
		// Extract the base addresses from the headers, put them into a list.
		std::vector<LPCVOID> addedMemRegionBaseAddresses(addedMemRegionHeadersCopy.size());

		std::transform(addedMemRegionHeadersCopy.begin(), addedMemRegionHeadersCopy.end(), addedMemRegionBaseAddresses.begin(), [](const MEMORY_BASIC_INFORMATION& e)
		{
			return e.BaseAddress;
		});

		const bool isAdded = std::find(addedMemRegionBaseAddresses.begin(), addedMemRegionBaseAddresses.end(), memRegionHeader.BaseAddress) != addedMemRegionBaseAddresses.end();

		const bool isFree = memRegionHeader.State == MEM_FREE;

		const bool isSystemSharedDataPage = memRegionHeader.BaseAddress >= Util::System::KUSER_SHARED_DATA && memRegionHeader.BaseAddress <= (void*)0x7FFFFFFF; // TODO Max user space address, replace with constant

		return isAdded || isFree || isSystemSharedDataPage;
	};

	currentMemRegionHeaders.erase(std::remove_if(currentMemRegionHeaders.begin(), currentMemRegionHeaders.end(), removalPredicate), currentMemRegionHeaders.end());

	// Sort on base address.
	std::sort(currentMemRegionHeaders.begin(), currentMemRegionHeaders.end(), [](const MEMORY_BASIC_INFORMATION& a, const MEMORY_BASIC_INFORMATION& b)
	{
		return a.BaseAddress < b.BaseAddress;
	});

	printf("\n");

	DWORD numCurrentMemRegionHeadersChecked = 0;

	DWORD recordedMemRegionsIndex = 0;
	const auto recordedMemRegionsIndexIsOutOfBounds = [&]()
	{
		return recordedMemRegionsIndex >= recordedMemRegions.size();
	};

	for (const auto& currentMemRegionHeader : currentMemRegionHeaders)
	{
		const auto recHdr = recordedMemRegions[recordedMemRegionsIndex]->header;
		const auto curHdr = currentMemRegionHeader;

		const void* recHdrAllocBase = recHdr.AllocationBase;
		DWORD recHdrProtection = convertMappedViewProtectionToPrivateRegionProtection(recHdr.Protect);

		// Go to the next iteration. If we need to merge, we have the next header available to check,
		// and if we don't, we still got the next recorded header for the next outer loop iteration.
		recordedMemRegionsIndex++;

		// Because we're recreating the address space using private allocations only, this means we have to convert
		// some protection constants (WRITECOPY etc.) which are only applicable to mapped views into VirtualAlloc-friendly
		// protection constants. When we do this, previous regions that were e.g. READWRITE-WRITECOPY-READWRITE then gets
		// converted to READWRITE x3, and so they merge together and become one big region since they share the same protection.
		// The problem now is that we'll try to compare memory regions, but since some regions were merged we won't be able to match them.
		//
		// To remedy this we manually count the sizes of the regions that were merged, and when we do our comparison we compare
		// the whole merged region instead of the individual regions (that don't exist anymore in the recreated address space).
		// We use an iterator so that if this phenomenon actually occurred we can just continue with the main comparison loop afterwards,
		// since we've iterated past all regions that are part of the merged region. Similar to the MEM_IMAGE stuff we did when
		// recreating the address space, we'll have to rely on the syscall log saying it's still those 3 regions, and not 1 bigger merged one.
		// It shouldn't be a problem as long as their access semantics remain the same.
		DWORD mergedRecHdrRegionSize = recHdr.RegionSize;

		while (!recordedMemRegionsIndexIsOutOfBounds())
		{
			const auto nextRecHdr = recordedMemRegions[recordedMemRegionsIndex]->header;

			// Not the same allocation base?
			// Then there's no point doing anything further since regions with different allocation bases cannot be merged.
			if (nextRecHdr.AllocationBase != recHdrAllocBase)
				break;

			// Protections do not match?
			if (convertMappedViewProtectionToPrivateRegionProtection(nextRecHdr.Protect) != recHdrProtection)
				break;

			mergedRecHdrRegionSize += nextRecHdr.RegionSize;
			recordedMemRegionsIndex++;
		}

		// Note:
		// Skipping AllocationProtect since we recreated the address space with an initial protection of PAGE_EXECUTE_READWRITE
		// for the most freedom to change access later, and Type, because when recreating we use private allocations only, even if
		// the original allocation was a mapped view or an image. Also, it doesn't matter if the original region was WRITECOPY-something,
		// because the replayed program won't know. The syscall log says it's WRITECOPY, and if they access the memory, well, then it
		// would get copied originally, but they won't know whether it was or not during the replay, so it should be fine to just set
		// it as PAGE_EXECUTE_READWRITE etc. for both initial and current, whatever is necessary.
		const bool headersMatch = curHdr.BaseAddress == recHdr.BaseAddress &&
			curHdr.AllocationBase == recHdr.AllocationBase &&
			curHdr.RegionSize == mergedRecHdrRegionSize &&
			curHdr.State == recHdr.State &&
			curHdr.Protect == recHdrProtection;

		if (!headersMatch)
		{
			printf("Memory region headers not matching (recorded vs current):\n");
			Util::PrintMemoryRegionHeader(recHdr);
			Util::PrintMemoryRegionHeader(curHdr);
			printf("******************\n");
			ExitProcess(-1);
		}

		numCurrentMemRegionHeadersChecked++;

		// Exiting here even if not all current memory regions have been checked. We verify if they have below.
		if (recordedMemRegionsIndexIsOutOfBounds())
		{
			break;
		}
	}

	if (numCurrentMemRegionHeadersChecked != currentMemRegionHeaders.size())
	{
		throw std::exception("Didn't check all current memory regions. It is possible the recorded memory region iterator exited the loop prematurely if the two lists don't match in logical size (remember, some merging happens, so can't just compare recorded size vs current size)");
	}

	if (recordedMemRegionsIndex != recordedMemRegions.size())
	{
		throw std::exception("Did not reach end of recorded memory regions list with index. In other words, there are fewer current regions than recorded regions, since both 'iterators' should increment alongside each other");
	}

	printf("Current memory region headers match recorded memory region headers\n");
}

void verifyAddressSpaceMemoryContentsMatchesRecordedMemoryContents(
	const Util::SmartHandle& hReplayProcess,
	const std::vector<std::shared_ptr<RecordedMemoryRegion>>& recordedMemRegions
)
{
	for (const auto& recordedMemRegion : recordedMemRegions)
	{
		if (recordedMemRegion->header.State != MEM_COMMIT) continue;
		if (!recordedMemRegion->containsData()) throw std::exception("Recorded memory region does not contain any data"); // TODO Can this even happen?

		const auto baseAddress = recordedMemRegion->header.BaseAddress;
		const auto regionSize = recordedMemRegion->header.RegionSize;

		// Allocate some temporary memory for the bytes we'll read from the replay process.
		unsigned char* pBytesInReplayProcess = (unsigned char*)malloc(regionSize);
		util_assert(pBytesInReplayProcess);

		// Read the region from the replay process.
		Util::MemoryRegion memRegion(hReplayProcess, (void*)baseAddress, regionSize);
		memRegion.DisablePageGuard();
		memRegion.ReadData(pBytesInReplayProcess, regionSize);
		memRegion.RevertToPreviousProtection();

		// Compare each byte in the read region to that in the recording.
		for (DWORD offset = 0; offset < regionSize; offset++)
		{
			const unsigned char currentByte = pBytesInReplayProcess[offset];
			const unsigned char recordedByte = *((unsigned char*)recordedMemRegion->data.get() + offset);

			if (currentByte != recordedByte)
			{
				std::stringstream errorMsg;
				errorMsg << std::hex << std::uppercase << std::setfill('0') << std::setw(2);
				errorMsg << "Current byte (0x" << static_cast<unsigned int>(currentByte) << ") does not match recorded byte (0x" << static_cast<unsigned int>(recordedByte) << ") at address " << (unsigned char*)baseAddress + offset;
				throw std::exception(errorMsg.str().c_str());
			}
		}

		free(pBytesInReplayProcess);
	}

	printf("Current memory contents match recorded memory contents\n");
}

void verifyAddressSpaceMatchesRecording(
	const Util::SmartHandle& hReplayProcess,
	const RecordedMemRegionsFromDisk& recordedMemRegionsFromDisk,
	const std::vector<MEMORY_BASIC_INFORMATION>& addedMemRegionHeaders,
	const std::vector<LPCVOID>& recordedThreadTEBAddrs
)
{
	// Merge recorded memory regions (mem + TEBs + PEB) into a single list and sort it by base address.
	const DWORD numPebRegions = 1; // TODO 0x7EFDF000
	auto allRecordedMemRegions = std::vector<std::shared_ptr<RecordedMemoryRegion>>();
	allRecordedMemRegions.reserve(recordedMemRegionsFromDisk.memRegions.size() + recordedMemRegionsFromDisk.tebRegions.size() + numPebRegions);

	allRecordedMemRegions.insert(allRecordedMemRegions.end(), recordedMemRegionsFromDisk.memRegions.begin(), recordedMemRegionsFromDisk.memRegions.end());
	allRecordedMemRegions.insert(allRecordedMemRegions.end(), recordedMemRegionsFromDisk.tebRegions.begin(), recordedMemRegionsFromDisk.tebRegions.end());
	allRecordedMemRegions.push_back(recordedMemRegionsFromDisk.pebRegion);

	std::sort(allRecordedMemRegions.begin(), allRecordedMemRegions.end(),
		[](const std::shared_ptr<RecordedMemoryRegion>& a, const std::shared_ptr<RecordedMemoryRegion>& b)
		{
			return a->header.BaseAddress < b->header.BaseAddress;
		}
	);

	// Move on to checking the address space.
	verifyAddressSpaceMemoryRegionHeadersMatchRecording(hReplayProcess, allRecordedMemRegions, addedMemRegionHeaders, recordedThreadTEBAddrs);
	verifyAddressSpaceMemoryContentsMatchesRecordedMemoryContents(hReplayProcess, allRecordedMemRegions);
}

DirectlyRecreateAddressSpaceReturnValues directlyRecreateAddressSpace(const RecordedMemRegionsFromDisk& recordedMemRegionsFromDisk)
{
	const PROCESS_INFORMATION replayProcessInfo = spawnReplayProcess();
	printf("Spawned process with ID %u (%04X)\n", replayProcessInfo.dwProcessId, replayProcessInfo.dwProcessId);

	const Util::SmartHandle hReplayProcess = Util::SmartHandle(replayProcessInfo.hProcess, NULL);
	Util::Thread replayProcessMainThread(replayProcessInfo.dwThreadId, replayProcessInfo.dwProcessId);

	int3break();

	// ---------------

	// Retrieve recorded memory regions.
	const auto recordedMemRegions = recordedMemRegionsFromDisk.memRegions;
	const auto recordedTebRegions = recordedMemRegionsFromDisk.tebRegions;
	const auto recordedPebRegion = recordedMemRegionsFromDisk.pebRegion;

	std::vector<LPCVOID> recordedThreadTEBAddrs;
	for (const auto& recordedTebRegion : recordedTebRegions) recordedThreadTEBAddrs.push_back(recordedTebRegion->header.AllocationBase);

	std::vector<MEMORY_BASIC_INFORMATION> recordedMemRegionHeaders;
	for (const auto& recordedMemRegion : recordedMemRegions) recordedMemRegionHeaders.push_back(recordedMemRegion->header);

	printf("Retrieved memory regions from disk\n");

	// ---------------

	const auto replayProcessMemStateBeforeDoingAnything = Util::System::GetMemoryRegionHeaders(replayProcessInfo.dwProcessId);

	// ---------------

	// Reserve recorded memory regions.
	const auto recordedMemRegionHeadersToReserve = getRecordedMemRegionHeadersToReserve(recordedMemRegions);
	for (const auto& x : recordedMemRegionHeadersToReserve) printf("%u ", x.BaseAddress); // Ignore this, needs to be here or we can't run without a debugger due to some weird race condition bug or something
	const auto successfullyReservedBaseAddresses = reserveRecordedMemoryRegions(hReplayProcess, recordedMemRegionHeadersToReserve);

	const auto replayProcessMemStateAfterReservingRecordedRegions = Util::System::GetMemoryRegionHeaders(replayProcessInfo.dwProcessId);

	printf("Reserved recorded memory regions\n");

	// ---------------

	// Inject MiraiReplayerDll.
	const auto replayProcessMemStateBeforeInjection = Util::System::GetMemoryRegionHeaders(replayProcessInfo.dwProcessId);

	LPCVOID injectedReplayerDllBaseAddr = Util::InjectDll(hReplayProcess, replayerDllPath);
	Util::Module replayerDll(hReplayProcess, (void*)injectedReplayerDllBaseAddr);

	const auto replayProcessMemStateAfterInjection = Util::System::GetMemoryRegionHeaders(replayProcessInfo.dwProcessId);
	const auto memRegionsAddedByInjection = getAddedMemRegions(replayProcessMemStateBeforeInjection, replayProcessMemStateAfterInjection);

	printf("Injected MiralReplayerDll\n");

	// ---------------

	Util::Thread::CreateRemote(hReplayProcess, replayProcessInfo.dwProcessId, replayerDll.GetExportedFunctionByName("prepareComm").addr, NULL);
	printf("Prepared comm with replayer\n");

	// ---------------

	// Start a thread at MiraiReplayerDll#threadWaitAreaEntryPoint.
	// WARNING! Ensure all allocations don't interfere with recorded memory regions.
	const auto replayProcessMemStateBeforeCreatingThreadAtWaitArea = Util::System::GetMemoryRegionHeaders(replayProcessInfo.dwProcessId);

	createThreadAtMiraiReplayerDllThreadWaitAreaEntryPoint(hReplayProcess, injectedReplayerDllBaseAddr);

	const auto replayProcessMemStateAfterCreatingThreadAtWaitArea = Util::System::GetMemoryRegionHeaders(replayProcessInfo.dwProcessId);
	const auto memRegionsAddedByCreatingThreadAtThreadWaitArea = getAddedMemRegions(replayProcessMemStateBeforeCreatingThreadAtWaitArea, replayProcessMemStateAfterCreatingThreadAtWaitArea);

	if (Util::System::GetThreadIds(replayProcessInfo.dwProcessId).size() != 2) throw std::exception("ASSERTION ERROR: Should only be DLL thread and main thread");
	
	// TODO Assert the TEB we received isn't occupied by the recorded TEBs (including those in the syscall log).
	// If this occurs we have to redo the "give me a TEB!" step, with new threads and everything.
	// Can probably just abort and restart the program, even. Whatever is simplest, the chance for this collision should be really low.

	printf("Created thread at MiraiReplayerDll#ThreadWaitAreaEntryPoint\n");

	// ---------------

	const auto replayProcessMainThreadTeb32MemRegionHeader = Util::MemoryRegion(hReplayProcess, (void*)replayProcessMainThread.GetTEBBaseAddr(), 0).GetHeader();

	// Kill main thread of replay process.
	// Keep this here, later we clear its TEB region since it can't be freed, have to make sure it's killed by then.
	replayProcessMainThread.Terminate(0);
	if (Util::System::GetThreadIds(replayProcessInfo.dwProcessId).size() != 1) throw std::exception("ASSERTION ERROR: Should only be DLL thread");

	printf("Killed main thread of replay process\n");

	// ---------------

	Util::Thread waitingThread(Util::System::GetThreadIds(replayProcessInfo.dwProcessId)[0], replayProcessInfo.dwProcessId);

	const auto replayProcessMemStateBeforeReservingTebsToBeFilled = Util::System::GetMemoryRegionHeaders(replayProcessInfo.dwProcessId);

	// There are some reserved regions accessible by the system only. We can't reserve or commit there.
	// What we can do is create TEBs there and overwrite them since they are writable.
	// Note that we do this while the recorded regions are reserved, so the new thread stacks etc. don't interfere with the recording.
	// Also have to kill the main thread and avoid it taking up a TEB that we'll reserve-to-fill below.
	// Also can't create a (temporary?) remote thread to do the main work since that'll occupy one of the TEBs we'll probably want to reserve-to-fill.
	const auto tempThreadIdsHoldingTebs = createThreadsInReplayProcessWithTEBs(hReplayProcess, replayProcessInfo.dwProcessId, recordedThreadTEBAddrs, injectedReplayerDllBaseAddr, waitingThread);
	if (tempThreadIdsHoldingTebs.size() != recordedThreadTEBAddrs.size()) throw std::exception("ASSERTION ERROR: Num temp threads holding TEBs does not equal num of TEBs to be reserved");
	
	// TODO What about those TEBs that were not in system-reserved areas and that we ourselves reserved earlier?

	const auto replayProcessMemStateAfterReservingTebsToBeFilled = Util::System::GetMemoryRegionHeaders(replayProcessInfo.dwProcessId);
	const auto memRegionsAddedByReservingTebsToBeFilled = getAddedMemRegions(replayProcessMemStateBeforeReservingTebsToBeFilled, replayProcessMemStateAfterReservingTebsToBeFilled);

	printf("Reserved recorded TEBs with temp threads\n");

	printf("\nDeleting memory regions added when reserving TEBs-to-be-filled:\n");

	// Delete the regions that were just created, except for the TEBs.
	std::set<LPCVOID> freedAllocationBases;
	for (const auto& addedMemRegion : memRegionsAddedByReservingTebsToBeFilled)
	{
		// Skip if allocation base matches a reserved TEB-to-be-filled.
		if (std::find(recordedThreadTEBAddrs.begin(), recordedThreadTEBAddrs.end(), addedMemRegion.AllocationBase) != recordedThreadTEBAddrs.end())
		{
			continue;
		}

		// Already freed that allocation base?
		if (freedAllocationBases.find(addedMemRegion.AllocationBase) != freedAllocationBases.end())
		{
			continue;
		}

		Util::PrintMemoryRegionHeader(addedMemRegion);

		Util::MemoryRegion::Free(hReplayProcess, addedMemRegion.AllocationBase);
		freedAllocationBases.insert(addedMemRegion.AllocationBase);
	}

	// ---------------

	// Ascertain which memory regions were added to the address space (injected DLL, new thread TEB/stack/other, and so on).
	const auto replayProcessMemStateBeforeReleasingReservedRecordedRegions = Util::System::GetMemoryRegionHeaders(replayProcessInfo.dwProcessId);
	auto addedMemRegions = getAddedMemRegions(replayProcessMemStateAfterReservingRecordedRegions, replayProcessMemStateBeforeReleasingReservedRecordedRegions);

	printf("\nOverall added memory regions (excluding mem regions added when reserving TEBs-to-be-filled, as they've been freed already, and excluding TEBs-to-be-filled themselves):\n");
	for (const auto& addedMemRegion : addedMemRegions) Util::PrintMemoryRegionHeader(addedMemRegion);

	// ---------------

	// Remove the reserved recorded regions.
	releaseReservedRecordedMemRegions(hReplayProcess, successfullyReservedBaseAddresses);

	printf("Removed reserved recorded regions\n");

	// ---------------

	void* nextBlockAddr = (void*)Util::Thread::CreateRemote(
		hReplayProcess,
		replayProcessInfo.dwProcessId,
		replayerDll.GetExportedFunctionByName("getNextBlockAddr").addr,
		NULL
	).GetExitCode();

	printf("Acquired nextBlockAddr=%08X\n", nextBlockAddr);

	// ---------------

	// Clear the address space.
	// Don't remove memory regions we added ourselves (injected DLL, new thread space, etc.), and a few others that are irremovable anyway.
	auto memRegionHeadersToSkip = addedMemRegions;
	memRegionHeadersToSkip.push_back(replayProcessMainThreadTeb32MemRegionHeader);
	memRegionHeadersToSkip.push_back(Util::MemoryRegion(hReplayProcess, (void*)Util::System::Unknown_Base, 0).GetHeader());

	clearAddressSpace(hReplayProcess, replayProcessInfo.dwProcessId, memRegionHeadersToSkip);

	printf("Cleared the address space\n");

	// ---------------

	// Print out added memory regions on every step.
	printf("\nMemory regions added after injecting DLL:\n");
	for (const auto& memRegion : memRegionsAddedByInjection) Util::PrintMemoryRegionHeader(memRegion);

	printf("\nMemory regions added after creating thread at threadWaitAreaEntryPoint:\n");
	for (const auto& memRegion : memRegionsAddedByCreatingThreadAtThreadWaitArea) Util::PrintMemoryRegionHeader(memRegion);

	printf("\nMemory regions added after reserving TEBs-to-be-filled:\n");
	for (const auto& memRegion : memRegionsAddedByReservingTebsToBeFilled) Util::PrintMemoryRegionHeader(memRegion);

	// ---------------

	printf("\nVerifying address space was cleared properly\n");

	std::vector<LPCVOID> memRegionBaseAddrsToSkip;
	memRegionBaseAddrsToSkip.push_back((char*)replayProcessMainThreadTeb32MemRegionHeader.BaseAddress - Util::System::TEB32_Offset);
	memRegionBaseAddrsToSkip.push_back(Util::System::PEB_Base);
	memRegionBaseAddrsToSkip.push_back(Util::System::Unknown_Base);
	memRegionBaseAddrsToSkip.push_back(Util::System::KUSER_SHARED_DATA);
	memRegionBaseAddrsToSkip.push_back((char*)Util::System::KUSER_SHARED_DATA + Util::System::PageSize); // It's the reserved remainder of the allocation

	verifyAddressSpaceWasCleared(
		replayProcessMemStateBeforeDoingAnything,
		Util::System::GetMemoryRegionHeaders(replayProcessInfo.dwProcessId),
		memRegionBaseAddrsToSkip
	);

	printf("Verified address space was cleared\n");

	// ---------------

	// Recreate the address space from the recording.
	recreateAddressSpaceFromRecording(hReplayProcess, recordedMemRegions, recordedTebRegions, recordedPebRegion);

	printf("Recreated address space from recording\n");

	// ---------------

	verifyAddressSpaceMatchesRecording(hReplayProcess, recordedMemRegionsFromDisk, addedMemRegions, recordedThreadTEBAddrs);
	printf("Recreated address space matches recorded address space\n");

	// ---------------

	DirectlyRecreateAddressSpaceReturnValues returnValues;
	returnValues.replayProcessId = replayProcessInfo.dwProcessId;
	returnValues.waitingThreadId = waitingThread.GetId();
	returnValues.replayerDllBaseAddr = (void*)injectedReplayerDllBaseAddr;
	returnValues.nextBlockAddr = nextBlockAddr;
	return returnValues;
}