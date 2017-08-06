#include "process.h"
#include "common.h"
#include "thread.h"
#include "memory_region.h"
#include <TlHelp32.h>

namespace Util
{
	ProcessId Process::GetId() const
	{
		return id;
	}

	const SmartHandle& Process::GetHandle() const
	{
		return handle;
	}

	std::vector<ThreadId> Process::GetThreadIds() const
	{
		std::vector<ThreadId> threadIds;

		// Take a snapshot of all processes' thread information. Second argument is ignored with TH32CS_SNAPTHREAD.
		const SmartHandle hProcessSnapshot = SmartHandle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0), INVALID_HANDLE_VALUE);

		// Collect all thread IDs for the specified process. See Thread32First and Thread32Next for how to use this API properly.
		//
		// Note: This code is a modified version of something I found on StackOverflow, but for some reason I did not include the author
		// to give credit. Searching for it gave me multiple results, all showing very similar code, so I'm not able to verify who
		// wrote it. It's not that important as the code is the standard way of doing this task as shown on MSDN, but I'm just mentioning it.
		THREADENTRY32 threadEntry;
		threadEntry.dwSize = sizeof(threadEntry);

		if (Thread32First(hProcessSnapshot.GetValue(), &threadEntry))
		{
			do {
				// Verify we've received the owner process ID member in the struct.
				UTIL_ASSERT(threadEntry.dwSize >= (FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(threadEntry.th32OwnerProcessID)));

				if (threadEntry.th32OwnerProcessID == id)
				{
					threadIds.push_back(threadEntry.th32ThreadID);
				}

				threadEntry.dwSize = sizeof(threadEntry);
			} while (Thread32Next(hProcessSnapshot.GetValue(), &threadEntry));
		}

		return threadIds;
	}

	std::vector<Thread> Process::GetThreads() const
	{
		std::vector<Thread> threads;

		for (const auto& threadId : GetThreadIds())
		{
			threads.emplace_back(Thread(threadId, this->id));
		}

		return threads;
	}

	std::vector<MEMORY_BASIC_INFORMATION> Process::GetMemoryRegionHeaders() const
	{
		std::vector<MEMORY_BASIC_INFORMATION> headers;

		// GetNativeSystemInfo used for WOW64.
		SYSTEM_INFO systemInfo;
		GetNativeSystemInfo(&systemInfo);

		const void* baseAddr = 0;
		MEMORY_BASIC_INFORMATION memBasicInfo;

		while (baseAddr < systemInfo.lpMaximumApplicationAddress)
		{
			if (!VirtualQueryEx(handle.GetValue(), baseAddr, &memBasicInfo, sizeof(memBasicInfo)))
			{
				// Exceeded scannable memory?
				if (GetLastError() == ERROR_INVALID_PARAMETER)
				{
					break;
				}
				// Or did an error occur?
				else
				{
					UTIL_THROW_WIN32("VirtualQueryEx failed");
				}
			}

			headers.push_back(memBasicInfo);
			baseAddr = (unsigned char*)memBasicInfo.BaseAddress + memBasicInfo.RegionSize;
		}

		return headers;
	}

	std::vector<MemoryRegion> Process::GetMemoryRegions() const
	{
		std::vector<MemoryRegion> memRegions;

		for (const auto& memRegionHeader : GetMemoryRegionHeaders())
		{
			memRegions.emplace_back(MemoryRegion(handle, memRegionHeader.BaseAddress, memRegionHeader.RegionSize));
		}

		return memRegions;
	}
}