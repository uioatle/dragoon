#include "lib\Util\include\process.h"
#include "lib\Util\include\system.h"
#include "lib\Util\include\smart_handle.h"
#include "lib\Util\include\memory_region.h"

#include <string>
#include <functional>
#include <Windows.h>

__declspec(noinline) void ReallocatePrivateMemoryRegionsWithWriteWatchingEnabled(Util::Process& parentProcess)
{
	const auto memRegionHeaders = parentProcess.GetMemoryRegionHeaders();

	for (auto iter = memRegionHeaders.begin(); iter != memRegionHeaders.end(); iter++)
	{
		const auto memRegionHeader = *iter;

		// All regions above the address in the IF-clause tend to be unfreeable because they are reserved by the system, so no point continuing.
		// No freeing means no reallocation, which means no write watching. We can assume the threshold is at DragoonDll#Init()'s remote thread,
		// which we know exists since this process was spawned from inside that function. If the main thread got the TEB at 0x7EFDB000, the remote thread's
		// TEB will be at 0x7EFD8000. However, if the main thread got 0x7EFD8000, the next TEB should be at that addres -0x3000, so that should be the threshold.
		if (memRegionHeader.BaseAddress >= (void*)(0x7EFD8000 - 0x3000))
		{
			break;
		}

		if (memRegionHeader.Type != MEM_PRIVATE)
		{
			continue;
		}

		const auto forEachMemRegionHeaderInAllocation = [&](const std::function<void(const MEMORY_BASIC_INFORMATION& header, uint32_t i)>& f)
		{
			auto iter2 = iter;
			uint32_t i = 0;

			while (true)
			{
				if (iter2->AllocationBase != memRegionHeader.AllocationBase || iter2->State == MEM_FREE)
				{
					break;
				}

				f(*iter2, i);

				iter2++;
				i++;
			}
		};

		// Disable all page guards. All regions are going to be reallocated anyway, so makes no difference.
		forEachMemRegionHeaderInAllocation([&](const MEMORY_BASIC_INFORMATION& memSubRegionHeader, const uint32_t i)
		{
			Util::MemoryRegion memSubRegion(parentProcess.GetHandle(), memSubRegionHeader.BaseAddress, memSubRegionHeader.RegionSize);

			if (memSubRegion.IsGuarded())
			{
				memSubRegion.DisableGuard();
			}
		});

		// Calculate total size of the whole allocation (including all sub-regions).
		uint32_t totalAllocationSize = 0;

		forEachMemRegionHeaderInAllocation([&](const MEMORY_BASIC_INFORMATION& memSubRegionHeader, const uint32_t i)
		{
			totalAllocationSize += memSubRegionHeader.RegionSize;
		});

		// Backup all committed pages to temporary memory.
		auto tempRegionAddr = std::unique_ptr<unsigned char>(new unsigned char[totalAllocationSize]);

		forEachMemRegionHeaderInAllocation([&](const MEMORY_BASIC_INFORMATION& memSubRegionHeader, const uint32_t i)
		{
			if (memSubRegionHeader.State == MEM_COMMIT)
			{
				Util::MemoryRegion memSubRegion(parentProcess.GetHandle(), memSubRegionHeader.BaseAddress, memSubRegionHeader.RegionSize);
				memSubRegion.ReadData(tempRegionAddr.get() + (Util::System::PageSize * i), memSubRegionHeader.RegionSize);
			}
		});

		// Free original allocation (including all its sub-regions).
		Util::MemoryRegion::Free(parentProcess.GetHandle(), memRegionHeader.AllocationBase);

		// Re-allocate original allocation, but with write watching enabled.
		Util::MemoryRegion reallocatedMemRegion(parentProcess.GetHandle(), memRegionHeader.AllocationBase, totalAllocationSize);
		reallocatedMemRegion.Allocate(MEM_RESERVE | MEM_WRITE_WATCH, memRegionHeader.AllocationProtect);

		// Restore original state, protection and data for sub-regions.
		forEachMemRegionHeaderInAllocation([&](const MEMORY_BASIC_INFORMATION& memSubRegionHeader, const uint32_t i)
		{
			if (memSubRegionHeader.State == MEM_COMMIT)
			{
				Util::MemoryRegion memSubRegion(parentProcess.GetHandle(), memSubRegionHeader.BaseAddress, memSubRegionHeader.RegionSize);

				// Currently the whole allocation has just been reserved, so individual sub-regions must be committed before anything can be done to them.
				memSubRegion.Allocate(MEM_COMMIT, PAGE_READWRITE);

				// Restore data.
				memSubRegion.WriteData(tempRegionAddr.get() + (Util::System::PageSize * i), memSubRegionHeader.RegionSize);

				// If the sub-region had a page guard, it would be problematic to restore the protection in the call above to VirtualAllocEx.
				// Therefore we instead restore the original protection after having restored the data, to avoid page guard violations.
				memSubRegion.ChangeProtection(memSubRegionHeader.Protect);
			}
		});

		// Skip ahead to the next allocation base.
		while (iter->AllocationBase == memRegionHeader.AllocationBase) iter++;
		iter--; // for-loop does the last iteration
	}
}

int main(int argc, char** argv)
{
	try
	{
		const uint32_t parentProcessId = std::stoi(argv[1]);
		const auto hParentProcess = Util::SmartHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentProcessId), NULL);
		auto parentProcess = Util::Process(hParentProcess, parentProcessId);

		ReallocatePrivateMemoryRegionsWithWriteWatchingEnabled(parentProcess);
	}
	catch (const std::exception& e)
	{
		return 1;
	}
	catch (...)
	{
		return 2;
	}

	return 0;
}