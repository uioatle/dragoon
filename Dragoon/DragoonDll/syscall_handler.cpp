#include "syscall_handler.h"
#include "checksum.h"

#include "DragoonGlobal\common.h"
#include "DragoonGlobal\events.h"

#include "lib\Util\include\smart_handle.h"
#include "lib\Util\include\memory_region.h"
#include "lib\Util\include\hook.h"
#include "lib\Util\include\windefs.h"
#include "lib\Util\include\system.h"
#include "lib\Util\include\fast_bitset_map.h"

#include <functional>
#include <sstream>
#include <list>
#include <Windows.h>

// Note:
// For some reason the compiler may push something on the stack that it doesn't pop off later,
// so don't hesitate to force noinline on every function that works inside a syscall to keep your sanity!
namespace Dragoon
{
	namespace SyscallHandler
	{
		static Util::Process* process;
		static Util::Module* dragoonDll;
		static Util::NativeMemoryAllocator* nativeAllocator;
		static SyscallHandler::RecordingInfo recordingInfo;

		static Util::Hook* syscallInterfaceHook;

		static MEMORY_BASIC_INFORMATION probedRegionMemRegionHeader;
		static MEMORY_BASIC_INFORMATION localeRegionMemRegionHeader;

		static Util::Windows::NativeApi::NtQueryVirtualMemory fpNtQueryVirtualMemory = nullptr;
		static Util::Windows::NativeApi::NtResetWriteWatch fpNtResetWriteWatch = nullptr;
		static Util::Windows::NativeApi::NtGetWriteWatch fpNtGetWriteWatch = nullptr;

		static inline Util::Lock& GetMemoryLock()
		{
			return *recordingInfo.memoryLock;
		}

		static inline ThreadRecordingInfo& GetThreadRecordingInfo(const Util::ThreadId threadId)
		{
			return recordingInfo.fpGetThreadRecordingInfo(threadId);
		}

		static inline ThreadInfo* GetThreadInfo(const Util::ThreadId threadId)
		{
			return recordingInfo.fpGetThreadInfo(threadId);
		}

		static inline uint32_t GetThreadInfosSize()
		{
			return recordingInfo.threadInfosSize;
		}

		static inline void EnableRecordingOfThread(const Util::ThreadId threadId)
		{
			return recordingInfo.fpEnableRecordingOfThread(threadId);
		}

		static inline void DisableRecordingOfThread(const Util::ThreadId threadId)
		{
			return recordingInfo.fpDisableRecordingOfThread(threadId);
		}

		static inline bool IsThreadBeingRecorded(const Util::ThreadId threadId)
		{
			return recordingInfo.fpIsThreadBeingRecorded(threadId);
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		// Syscall information needs to be thread-local otherwise thread switches will cause race conditions.
		// This isn't only relevant when recording, but also while the application is executing normally, it might have multiple threads.
		struct SyscallInfo
		{
			Util::ThreadId threadId;
			uint32_t eax, ebx, ecx, edx, esi, edi, esp;
		};

		struct SyscallReturnContext
		{
			// Warning: Do not name these members as in SyscallInfo, or we'll get Error C2410 ("[...] because when we have a field name that
			// has been used also in other struturre, the compiler will gives the error", http://www.trlevelmanager.eu/plugin_sdk_help/combine_asm_with_c.htm)
			uint32_t _eax, _ecx, _edx;
		};

		// ---------------------------------------------------------------------------------------------------------------------------------------

		static enum IterateMemRegionHeadersReturnValues : uint32_t
		{
			GoToNextRegion = -1,
			StopIterating = -2
		};

		// The passed-in function returns one of the expected IterateMemRegionHeadersReturnValues constants or how many bytes from the current base address to skip past to reach the next region to query.
		// Starts past the NULL region and stops at KUSER_SHARED_DATA (the last 64kB are off limits anyway) if no start- and end addresses are specified (nullptr).
		static NOINLINE void IterateMemRegionHeaders(
			void* _startAddr,
			void* _endAddr,
			std::function<uint32_t(const MEMORY_BASIC_INFORMATION& memRegionHeader)> handleMemRegionHeader
		)
		{
			MEMORY_BASIC_INFORMATION memBasicInfo;
			const HANDLE hProcess = process->GetHandle().GetValue();

			void* addr = _startAddr == nullptr ? (void*)0x10000 : _startAddr;
			void* endAddr = _endAddr == nullptr ? Util::System::KUSER_SHARED_DATA : _endAddr;

			while (addr < endAddr)
			{
				const NTSTATUS status = fpNtQueryVirtualMemory(hProcess, addr, Util::Windows::MemoryBasicInformation, &memBasicInfo, sizeof(memBasicInfo), NULL);

				if (!Util::Windows::IsNtSuccess(status))
				{
					// Exceeded scannable memory?
					if (status == STATUS_INVALID_PARAMETER)
					{
						break;
					}
					// Or did an error occur?
					else
					{
						DragoonGlobal::SafeAbort();
					}
				}

				const uint32_t returnValue = handleMemRegionHeader(memBasicInfo);

				if (returnValue == IterateMemRegionHeadersReturnValues::StopIterating)
				{
					break;
				}

				addr = (unsigned char*)memBasicInfo.BaseAddress + (returnValue == IterateMemRegionHeadersReturnValues::GoToNextRegion ? memBasicInfo.RegionSize : returnValue);
			}
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		static struct PageChecksum
		{
			void* pageAddr;
			uint32_t checksum;
		};

		// ---------------------------------------------------------------------------------------------------------------------------------------

		// CommentID='Page checksums memory pool'.
		// We need a list per CommittedRegion of PageChecksums with a total of 2GB/PageSize for all CommittedRegions combined.
		// The lists combined will exceed the stack space, and dynamically allocating and deleting them on every syscall is slow.
		// Instead we pre-allocate the necessary space and then just ask for a pointer to the next available slot that fits the amount
		// we need for the current committed region. Clearing this list is as simple as resetting the index, and no freeing is necessary.
		static std::unique_ptr<PageChecksum> _pageChecksumsMemoryPoolBaseAddr;
		static uint32_t _pageChecksumsMemoryPoolIndex;

		static NOINLINE void ResetPageChecksumsMemoryPool()
		{
			_pageChecksumsMemoryPoolIndex = 0;
		}

		static NOINLINE void InitPageChecksumsMemoryPool()
		{
			// Allocate a static block of memory big enough to contain 2GB/PageSize structs. This will cover a PageChecksum per page in the address space.
			_pageChecksumsMemoryPoolBaseAddr = std::unique_ptr<PageChecksum>(new PageChecksum[1024 * 1024 * 1024 * 2 / Util::System::PageSize]);
			ResetPageChecksumsMemoryPool();
		}

		static NOINLINE PageChecksum* GetNextPageChecksumSlotInPool(const uint32_t numRequestedPages)
		{
			const auto addr = &_pageChecksumsMemoryPoolBaseAddr.get()[_pageChecksumsMemoryPoolIndex];
			_pageChecksumsMemoryPoolIndex += numRequestedPages;
			return addr;
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		static class CommittedRegion
		{
		public:
			CommittedRegion(void* baseAddr, const uint32_t size) : baseAddr(baseAddr), size(size), pageChecksums(nullptr)
			{
			}
			
			// See CommentID='Page checksums memory pool'.
			inline PageChecksum* GetPageChecksums()
			{
				if (pageChecksums == nullptr)
				{
					pageChecksums = GetNextPageChecksumSlotInPool(GetNumPagesInRegion());
				}

				return pageChecksums;
			}

			inline void* GetBaseAddr() const
			{
				return baseAddr;
			}

			inline uint32_t GetSize() const
			{
				return size;
			}

			inline uint32_t GetNumPagesInRegion() const
			{
				return size / Util::System::PageSize;
			}
		private:
			void* baseAddr;
			uint32_t size;
			PageChecksum* pageChecksums;
		};

		static struct AllocationInfo
		{
			uint32_t size;
			bool shouldBeSkipped;

			// If the allocation should be skipped we don't care whether it's write watched or not, so this member will be set to 'false'.
			// The isWriteWatched and shouldBeSkipped members are mutually exclusive; only one of them will be used.
			bool isWriteWatched;

			// To avoid scanning the allocationInfos bitset for this struct record we instead reference it from a list which we'll call the 'iteration list'.
			// We keep an iterator to the corresponding list element so that we can easily delete it when we delete this struct.
			std::list<uint32_t>::iterator listElementIter;

			// List of committed regions within this allocation. Contains pairs of base address + region size. Pages within the regions are expected not to have page guards.
			// Important: Using two lists so it is possible to hold both old and new regions at the same time if necessary. The pointer points to the list current in use.
			std::vector<CommittedRegion> _committedRegions1;
			std::vector<CommittedRegion> _committedRegions2;

			std::vector<CommittedRegion>* committedRegions;
			std::vector<CommittedRegion>* committedRegionsBeforeSyscall;
		};

		// CommentID='Allocation index granularity explanation'.
		// There are 2GB/64kB allocations, so we should really have 32768 entries here.
		// However, TEBs and PEBs(?) don't follow the standard allocation granularity of 64kB and are instead 0x3000 each (at least for TEBs).
		// To avoid handling TEBs individually wherever we manipulate the allocation list we instead sacrifice some memory (16x more) to treat every allocationInfo uniformly across the code base.
		// We therefore need 2GB/PageSize indexes.
		Util::FastBitsetMap<524288, AllocationInfo> allocationInfos;

		// We use lists to avoid iterating over the bitset, which is slow. We use linked lists since we can quickly delete the element by keeping an iterator to the element.
		// The downside is that we must allocate every node instead of just reserving a block of memory. Compared to a vector you still don't have to move elements on deletion.
		// Following from this, the other iterators don't get invalidated like they do if we were to use a vector as elements don't have to be moved on deletion (important).
		// We keep a list of allocationsToBeSkipped as well, because we'd like to quickly check if those allocations were removed after a syscall so we can delete them from the allocation list (bitset).
		//
		// An AllocationInfo struct can only be referenced by one of these lists at once. The lists are used for quick reference of all allocations of the same type.
		// When a struct is deleted so is its list element. The struct therefore contains an iterator to the corresponding list so the removal may happen fast.
		std::list<uint32_t> allocationsToBeSkippedIndices;
		std::list<uint32_t> writeWatchedAllocationIndices;
		std::list<uint32_t> nonWriteWatchedAllocationIndices;

		static inline uint32_t AllocationBaseToAllocationListIndex(void* allocationBase)
		{
			return (uint32_t)allocationBase / Util::System::PageSize;
		}

		static inline void* AllocationListIndexToAllocationBase(const uint32_t allocationIndex)
		{
			return (void*)(allocationIndex * Util::System::PageSize);
		}

		static NOINLINE bool _ShouldAllocationBeSkipped(void* allocationBase)
		{
			// Skip allocation belonging to DragoonDll.
			if (allocationBase == dragoonDll->GetBaseAddress())
			{
				return true;
			}

			// Skip the native allocator's specially designated memory block.
			if (allocationBase == nativeAllocator)
			{
				return true;
			}

			// Skip allocations internal to DragoonDll (by the native allocator).
			if (nativeAllocator->WasAllocationBaseAllocatedByThisAllocator(allocationBase))
			{
				return true;
			}

			// Skip the wow64.dll module.
			if (allocationBase == recordingInfo.wow64DllAllocationBase)
			{
				return true;
			}

			// Skip WOW64 probed region.
			if (allocationBase == probedRegionMemRegionHeader.AllocationBase)
			{
				return true;
			}

			// Skip Locale region.
			if (allocationBase == localeRegionMemRegionHeader.AllocationBase)
			{
				return true;
			}

			// Does the allocation belong to a thread?
			// TODO Optimize this loop into O(1) if possible.
			for (uint32_t i = 0; i < GetThreadInfosSize(); ++i)
			{
				const ThreadInfo* threadInfo = GetThreadInfo(i);

				if (threadInfo)
				{
					if (allocationBase == threadInfo->stack32BitAllocationBase || allocationBase == threadInfo->stack64BitAllocationBase)
					{
						return true;
					}
				}
			}

			// All is good.
			return false;
		}

		static NOINLINE uint32_t RetrieveAllocationSize(void* allocationBase)
		{
			uint32_t allocationSize = 0;

			IterateMemRegionHeaders(allocationBase, nullptr, [&allocationBase, &allocationSize](const MEMORY_BASIC_INFORMATION& memRegionHeader)
			{
				if (memRegionHeader.AllocationBase != allocationBase)
				{
					return IterateMemRegionHeadersReturnValues::StopIterating;
				}

				allocationSize += memRegionHeader.RegionSize;
				return IterateMemRegionHeadersReturnValues::GoToNextRegion;
			});

			return allocationSize;
		}

		static NOINLINE bool _IsAllocationWriteWatched(void* allocationBase, const uint32_t allocationSize)
		{
			const NTSTATUS status = fpNtResetWriteWatch(process->GetHandle().GetValue(), allocationBase, allocationSize);

			if (!Util::Windows::IsNtSuccess(status))
			{
				// If error was STATUS_INVALID_PARAMETER_1 it means the allocation isn't write watched.
				if (status == 0xC00000EF)
				{
					return false;
				}
				// Otherwise it was an actual error.
				else
				{
					DragoonGlobal::SafeAbort();
				}
			}

			return true;
		}

		static NOINLINE void AddRegionToCommittedRegionsList(std::vector<CommittedRegion>& committedRegions, const MEMORY_BASIC_INFORMATION& memRegionHeader)
		{
			// See CommentID='Not checksumming regions with page guards' for info on why we skip guarded regions.
			const bool regionIsGuarded = memRegionHeader.Protect & PAGE_GUARD;

			if (memRegionHeader.State == MEM_COMMIT && !regionIsGuarded)
			{
				CommittedRegion committedRegion(memRegionHeader.BaseAddress, memRegionHeader.RegionSize);
				committedRegions.emplace_back(committedRegion);
			}
		}

		static NOINLINE void _InitCommittedRegionsList(AllocationInfo& allocationInfo, void* allocationBase)
		{
			// Set up the pointers to the vectors.
			allocationInfo.committedRegions = &allocationInfo._committedRegions1;
			allocationInfo.committedRegionsBeforeSyscall = &allocationInfo._committedRegions2;
			
			// Pre-allocate the vectors to avoid repeated allocations.
			allocationInfo.committedRegions->reserve(32);
			allocationInfo.committedRegionsBeforeSyscall->reserve(32);

			// Iterate over all regions in the current allocation.
			IterateMemRegionHeaders(allocationBase, nullptr, [&allocationInfo, &allocationBase](const MEMORY_BASIC_INFORMATION& memRegionHeader)
			{
				if (memRegionHeader.AllocationBase != allocationBase)
				{
					return IterateMemRegionHeadersReturnValues::StopIterating;
				}

				AddRegionToCommittedRegionsList(*allocationInfo.committedRegions, memRegionHeader);
				return IterateMemRegionHeadersReturnValues::GoToNextRegion;
			});
		}

		static inline uint32_t AddAllocationWithSizeToAllocationList(void* allocationBase, const uint32_t allocationSize)
		{
			const uint32_t allocationIndex = AllocationBaseToAllocationListIndex(allocationBase);

			// Already exists?
			if (allocationInfos.Test(allocationIndex))
			{
				return -1;
			}

			// See struct definition for info how these members are used.
			AllocationInfo _allocationInfo;

			// Add the new allocationInfo to the allocation list and immediately return a reference to it.
			// This way we can assign pointers to the struct's members without the struct being on the stack (when the struct is moved into the list the pointers still point to the stack).
			allocationInfos.Set(allocationIndex, _allocationInfo);
			AllocationInfo& allocationInfo = allocationInfos.Get(allocationIndex);

			// Only retrieve size if it wasn't given in as argument.
			allocationInfo.size = allocationSize == -1 ? RetrieveAllocationSize(allocationBase) : allocationSize;

			allocationInfo.shouldBeSkipped = _ShouldAllocationBeSkipped(allocationBase);
			allocationInfo.isWriteWatched = allocationInfo.shouldBeSkipped ? false : _IsAllocationWriteWatched(allocationBase, allocationInfo.size);

			// Add allocationInfo reference to iteration list.
			std::list<uint32_t>* list;

			if (allocationInfo.shouldBeSkipped)
			{
				list = &allocationsToBeSkippedIndices;
			}
			else if (allocationInfo.isWriteWatched)
			{
				list = &writeWatchedAllocationIndices;
			}
			else
			{
				list = &nonWriteWatchedAllocationIndices;
			}

			list->emplace_back(allocationIndex);
			allocationInfo.listElementIter = --list->end();

			// Initialize the list of committed regions (applies to regions being checksummed).
			// Only initialize list of committed regions if we intend to later checksum those regions (i.e. we're not skipping the allocation base or it's write watched).
			allocationInfo.committedRegions = nullptr;
			allocationInfo.committedRegionsBeforeSyscall = nullptr;

			if (!allocationInfo.shouldBeSkipped && !allocationInfo.isWriteWatched)
			{
				_InitCommittedRegionsList(allocationInfo, allocationBase);
			}

			// We're done. Return the size in case the caller needs it.
			return allocationInfo.size;
		}

		static NOINLINE uint32_t AddAllocationToAllocationList(void* allocationBase)
		{
			return AddAllocationWithSizeToAllocationList(allocationBase, -1);
		}

		static NOINLINE void RemoveAllocationFromAllocationList(void* allocationBase)
		{
			const uint32_t allocationIndex = AllocationBaseToAllocationListIndex(allocationBase);
			const auto& allocationInfo = allocationInfos.Get(allocationIndex);

			// Remove allocationInfo reference from iteration list.
			std::list<uint32_t>* list;
			
			if (allocationInfo.shouldBeSkipped)
			{
				list = &allocationsToBeSkippedIndices;
			}
			else if (allocationInfo.isWriteWatched)
			{
				list = &writeWatchedAllocationIndices;
			}
			else
			{
				list = &nonWriteWatchedAllocationIndices;
			}
			
			list->erase(allocationInfo.listElementIter); // Erasing from std::list does not invalidate other iterators, only the removed element

			// Remove allocationInfo from allocation list.
			allocationInfos.Clear(allocationIndex);
		}

		static NOINLINE void ClearAllocationList()
		{
			allocationInfos.Reset();

			allocationsToBeSkippedIndices.clear();
			writeWatchedAllocationIndices.clear();
			nonWriteWatchedAllocationIndices.clear();
		}

		static NOINLINE void PopulateAllocationList(const ThreadInfo& threadInfoOfThreadStartingRecording)
		{
			IterateMemRegionHeaders(nullptr, nullptr, [&](const MEMORY_BASIC_INFORMATION& memRegionHeader) -> uint32_t
			{
				if (memRegionHeader.AllocationBase == NULL || memRegionHeader.State == MEM_FREE)
				{
					return memRegionHeader.RegionSize;
				}

				// Skip allocations belonging to the thread starting the recording (it's a temporary thread).
				if (memRegionHeader.AllocationBase == threadInfoOfThreadStartingRecording.stack32BitAllocationBase ||
					memRegionHeader.AllocationBase == threadInfoOfThreadStartingRecording.stack64BitAllocationBase ||
					memRegionHeader.AllocationBase == threadInfoOfThreadStartingRecording.GetTEBAllocationBase())
				{
					return memRegionHeader.RegionSize;
				}

				const uint32_t allocationSize = AddAllocationToAllocationList(memRegionHeader.AllocationBase);
				return allocationSize;
			});
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		static NOINLINE void ResetWriteWatchingOnAllWriteWatchedAllocations()
		{
			const HANDLE hProcess = process->GetHandle().GetValue();

			for (const auto& allocationIndex : writeWatchedAllocationIndices)
			{
				const NTSTATUS status = fpNtResetWriteWatch(
					hProcess,
					AllocationListIndexToAllocationBase(allocationIndex),
					allocationInfos.Get(allocationIndex).size
				);

				if (!Util::Windows::IsNtSuccess(status))
				{
					// We expect all calls to be made on a write watched allocation, so even if the error is just that it wasn't write watched we consider that an error.
					DragoonGlobal::SafeAbort();
				}
			}
		}

		static NOINLINE void ChecksumPagesInRegion(const void* currentThreadsTebBaseAddr, CommittedRegion& committedRegion)
		{
			// Guarded regions will raise a STATUS_GUARD_PAGE_VIOLATION on access and abort the syscall.
			// When the syscall is re-tried by the application the guard will have been removed and the pages can
			// be checksummed as usual. We should trust the system not to remove the guard protections or
			// access guarded regions from kernel mode to reduce the implementation complexity of our solution.
			// In the event the aforementioned did happen we would need a more involved way to deal with it,
			// but that would degrade recording performance and considering that page guards are a "user mode
			// kind of mechanism", chances should be low that the kernel is going to try to interfere with it
			// instead of just letting the guard protections kick in naturally, e.g. when outgrowing a stack in user mode.
			// If the kernel pushes on the user mode stack is another story, however...
			//
			// tldr: We trust that the kernel will leave guarded regions alone and don't checksum them.

			// Can't just checksum the whole region because if there's a write we can't know which pages were written to
			// and we'd be forced to dump the whole region which would be really wasteful on space. Besides, since we'd
			// have to checksum based on every byte in the region it would essentially be the same as checksumming every page,
			// which is basically the same and has little performance difference. Additionally, if individual pages within
			// the region were decomitted after the syscall, this would be a problem since now we can't checksum the region anymore as expected.

			// Normally we would have to clear this list (very important), but not now since it's just a pointer to static memory.
			PageChecksum* pageChecksums = committedRegion.GetPageChecksums();
			const auto numPagesInRegion = committedRegion.GetNumPagesInRegion();

			for (uint32_t i = 0; i < numPagesInRegion; ++i)
			{
				const auto pageAddr = (unsigned char*)committedRegion.GetBaseAddr() + (Util::System::PageSize * i);
			
				PageChecksum pageChecksum;
				pageChecksum.pageAddr = pageAddr;
			
				// CommentID='Checksumming TEB before syscall'.
				// If page is TEB, skip first member (Current SEH frame). It is usually always updated and is an artifact of the syscall handler.
				// TODO Can probably move this out of the loop and check if the allocation is a TEB, then skip directly to TEB32 and hash those pages only or something.
				if (pageAddr == currentThreadsTebBaseAddr)
				{
					pageChecksum.checksum = checksum(pageAddr + sizeof(void*), Util::System::PageSize - sizeof(void*));
				}
				else
				{
					pageChecksum.checksum = checksum(pageAddr, Util::System::PageSize);
				}
				
				pageChecksums[i] = pageChecksum;
			}
		}

		static NOINLINE void ChecksumNonWriteWatchedRegions(const void* currentThreadsTebBaseAddr, const ThreadRecordingInfo& threadRecordingInfo)
		{
			// Important.
			ResetPageChecksumsMemoryPool();

			for (const auto& allocationIndex : nonWriteWatchedAllocationIndices)
			{
				for (auto& committedRegion : *allocationInfos.Get(allocationIndex).committedRegions)
				{
					ChecksumPagesInRegion(currentThreadsTebBaseAddr, committedRegion);
				}
			}
		}

		static NOINLINE void PrepareForMemoryComparison(const void* currentThreadsTebBaseAddr, const ThreadRecordingInfo& threadRecordingInfo)
		{
			ResetWriteWatchingOnAllWriteWatchedAllocations();
			ChecksumNonWriteWatchedRegions(currentThreadsTebBaseAddr, threadRecordingInfo);
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		// See comment CommentID='Allocation index granularity explanation' for info about size.
		static Util::FastBitset<524288> _allocationBasesAfterSyscall;

		// See comment CommentID='Handling added allocations' for more info.
		// Pair contains allocation base and allocation size.
		static std::vector<std::pair<void*, uint32_t>> _addedAllocations;

		static NOINLINE uint32_t _AllocationNotInList(void* allocationBase)
		{
			// Getting the size here is just an optimization so we can skip the other sub-regions. We'll have to retrieve the size later anyway.
			const auto allocationSize = RetrieveAllocationSize(allocationBase);

			_addedAllocations.emplace_back(std::make_pair(allocationBase, allocationSize));

			return allocationSize;
		}

		static NOINLINE uint32_t _AllocationAlreadyInList(
			bool& isGatheringCommittedRegions,
			void*& currentAllocationBase,
			AllocationInfo*& currentAllocationInfo,
			const uint32_t& allocationIndex,
			const MEMORY_BASIC_INFORMATION& memRegionHeader
		)
		{
			auto& allocationInfo = allocationInfos.Get(allocationIndex);

			// Skip past whole allocation if allocation should be skipped or if it's write watched.
			if (allocationInfo.shouldBeSkipped || allocationInfo.isWriteWatched)
			{
				return allocationInfo.size;
			}

			// If the allocation should be checksummed we need to start gathering committed regions,
			// so we enter a special mode so that every iteration until the next allocation only add committed regions.
			isGatheringCommittedRegions = true;
			currentAllocationBase = memRegionHeader.AllocationBase;
			currentAllocationInfo = &allocationInfo;

			// We'd like to keep the list of committed regions from before the syscall so we can compare their checksums before and after.
			// The problem is that we need to clear and re-fill this list with the current status of the allocation's committed regions, and we do it while iterating the memory to avoid iterating more than once.
			// The solution is to use the second list of committed regions for the refill and keep the old one, so we swap the pointers in order for the code to remain ignorant of this switch.
			std::vector<CommittedRegion>* temp = allocationInfo.committedRegions;
			allocationInfo.committedRegions = allocationInfo.committedRegionsBeforeSyscall;
			allocationInfo.committedRegionsBeforeSyscall = temp;

			// Very important to remember to clear the list.
			allocationInfo.committedRegions->clear();

			// Add the region we're currently at to the list of committed regions for this allocation before moving on to add the rest.
			AddRegionToCommittedRegionsList(*allocationInfo.committedRegions, memRegionHeader);

			return IterateMemRegionHeadersReturnValues::GoToNextRegion;
		}

		// Returns true if region was added to the committed regions list.
		// Returns false if region was not added because allocation reached its end. In this case the gathering mode has also been disabled.
		static NOINLINE bool _IsGatheringCommittedRegions(
			bool& isGatheringCommittedRegions,
			void*& currentAllocationBase,
			AllocationInfo*& currentAllocationInfo,
			const MEMORY_BASIC_INFORMATION& memRegionHeader
		)
		{
			if (memRegionHeader.AllocationBase != currentAllocationBase)
			{
				isGatheringCommittedRegions = false;
				return false;
			}

			AddRegionToCommittedRegionsList(*currentAllocationInfo->committedRegions, memRegionHeader);
			return true;
		}

		static NOINLINE uint32_t _IsNotGatheringCommittedRegions(
			Util::FastBitset<524288>& allocationBasesAfterSyscall,
			bool& isGatheringCommittedRegions,
			void*& currentAllocationBase,
			AllocationInfo*& currentAllocationInfo,
			const MEMORY_BASIC_INFORMATION& memRegionHeader
		)
		{
			const auto allocationIndex = AllocationBaseToAllocationListIndex(memRegionHeader.AllocationBase);

			// Add the current allocation base to a bitset to announce it existed after the syscall.
			allocationBasesAfterSyscall.Set(allocationIndex);

			// Is this a new allocation?
			if (!allocationInfos.Test(allocationIndex))
			{
				return _AllocationNotInList(memRegionHeader.AllocationBase);
			}

			return _AllocationAlreadyInList(isGatheringCommittedRegions, currentAllocationBase, currentAllocationInfo, allocationIndex, memRegionHeader);
		}

		static NOINLINE std::vector<std::pair<void*, uint32_t>>& RetrieveAddedAllocationsAndUpdateCommittedRegionsLists(Util::FastBitset<524288>& allocationBasesAfterSyscall)
		{
			// Important!
			_addedAllocations.clear();

			bool isGatheringCommittedRegions = false;
			void* currentAllocationBase = nullptr;
			AllocationInfo* currentAllocationInfo = nullptr;

			IterateMemRegionHeaders(nullptr, nullptr, [&](const MEMORY_BASIC_INFORMATION& memRegionHeader) -> uint32_t
			{
				if (memRegionHeader.State == MEM_FREE)
				{
					return IterateMemRegionHeadersReturnValues::GoToNextRegion;
				}

				// Are we currently gathering committed regions for the current allocation (special mode)?
				if (isGatheringCommittedRegions)
				{
					// If the region is added to the committed regions list we move to the next region.
					// If not, the allocation has ended so we fall through to start directly on the next iteration without doing another query call (that is, we fall out of this if-clause).
					if (_IsGatheringCommittedRegions(isGatheringCommittedRegions, currentAllocationBase, currentAllocationInfo, memRegionHeader))
					{
						return IterateMemRegionHeadersReturnValues::GoToNextRegion;
					}
				}

				return _IsNotGatheringCommittedRegions(allocationBasesAfterSyscall, isGatheringCommittedRegions, currentAllocationBase, currentAllocationInfo, memRegionHeader);
			});

			return _addedAllocations;
		}

		static NOINLINE void HandleFreedAllocations(const Util::FastBitset<524288>& allocationBasesAfterSyscall, EventLogWriter& eventLogWriter)
		{
			const auto handleIfAllocationBaseWasFreed = [&](const uint32_t allocationIndex)
			{
				if (!allocationBasesAfterSyscall.Test(allocationIndex))
				{
					const auto freedAllocationBase = AllocationListIndexToAllocationBase(allocationIndex);

					RemoveAllocationFromAllocationList(freedAllocationBase);
					eventLogWriter.AddMemoryAllocationRemovedEvent(freedAllocationBase);
				}
			};

			for (const auto& allocationIndex : allocationsToBeSkippedIndices) handleIfAllocationBaseWasFreed(allocationIndex);
			for (const auto& allocationIndex : writeWatchedAllocationIndices) handleIfAllocationBaseWasFreed(allocationIndex);
			for (const auto& allocationIndex : nonWriteWatchedAllocationIndices) handleIfAllocationBaseWasFreed(allocationIndex);
		}

		static NOINLINE void HandleModificationsToWriteWatchedAllocations(const std::function<void(void* pageAddr)>& handleModifiedMemPageFunc)
		{
			const HANDLE hProcess = process->GetHandle().GetValue();

			for (const auto& writeWatchedAllocationIndex : writeWatchedAllocationIndices)
			{
				// Perform the NtGetWriteWatch syscall.
				PVOID writtenPageAddrs[1024 * 10];
				ULONG_PTR numWrittenPageAddrs = sizeof(writtenPageAddrs) / sizeof(PVOID);
				ULONG granularity = UTIL_SYSTEM_PAGE_SIZE;
				
				const NTSTATUS status = fpNtGetWriteWatch(
					hProcess,
					0,
					AllocationListIndexToAllocationBase(writeWatchedAllocationIndex),
					allocationInfos.Get(writeWatchedAllocationIndex).size,
					(PVOID*)&writtenPageAddrs,
					&numWrittenPageAddrs,
					&granularity
				);
				
				if (!Util::Windows::IsNtSuccess(status))
				{
					DragoonGlobal::SafeAbort();
				}
				
				// If any pages were modified, handle them.
				if (numWrittenPageAddrs > 0)
				{
					for (uint32_t i = 0; i < numWrittenPageAddrs; ++i)
					{
						handleModifiedMemPageFunc(writtenPageAddrs[i]);
					}
				}
			}
		}

		static NOINLINE void _ChecksumPagesInRegionAndHandleDetectedModifications(
			const void* currentThreadsTebBaseAddr,
			CommittedRegion& committedRegionBeforeSyscall,
			const std::function<void(void* pageAddr)>& handleModifiedMemPageFunc
		)
		{
			PageChecksum* pageChecksumsBeforeSyscall = committedRegionBeforeSyscall.GetPageChecksums();
			const auto numPagesInRegion = committedRegionBeforeSyscall.GetNumPagesInRegion();

			for (uint32_t i = 0; i < numPagesInRegion; ++i)
			{
				const auto& pageChecksumBeforeSyscall = pageChecksumsBeforeSyscall[i];

				// If page is TEB, skip first member (see CommentID='Checksumming TEB before syscall').
				const bool pageIsTeb = pageChecksumBeforeSyscall.pageAddr == currentThreadsTebBaseAddr;

				const unsigned char* pageAddr = pageIsTeb ?
					(unsigned char*)pageChecksumBeforeSyscall.pageAddr + sizeof(void*) :
					(unsigned char*)pageChecksumBeforeSyscall.pageAddr;

				const uint32_t length = pageIsTeb ?
					Util::System::PageSize - sizeof(void*) :
					Util::System::PageSize;

				__try
				{
					if (pageChecksumBeforeSyscall.checksum != checksum(pageAddr, length))
					{
						handleModifiedMemPageFunc(pageChecksumBeforeSyscall.pageAddr);
					}
				}
				__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
				{
					// If page is inaccessible that must mean either its protection was changed (maybe guarded), or it was decommitted, or the region it was in was freed.
					// We're not logging decommits due to reasons explained in the thesis, but if we were to do it this would be the place. Would have to make sure it was
					// actually a decommit in that case, however, and not just a protection change. We still cannot track all decommits here since write watched allocations
					// are not checked in this function, only non-write watched ones.
					// Note: This try-catch here may be a major bottleneck despite its 'elegancy'.
				};
			}
		}

		static NOINLINE void HandleModificationsToNonWriteWatchedAllocations(const void* currentThreadsTebBaseAddr, const std::function<void(void* pageAddr)>& handleModifiedMemPageFunc)
		{
			for (const auto& allocationIndex : nonWriteWatchedAllocationIndices)
			{
				// Note that we're not iterating the current committed regions but those saved from before the syscall.
				for (auto& committedRegionBeforeSyscall : *allocationInfos.Get(allocationIndex).committedRegionsBeforeSyscall)
				{
					_ChecksumPagesInRegionAndHandleDetectedModifications(currentThreadsTebBaseAddr, committedRegionBeforeSyscall, handleModifiedMemPageFunc);
				}
			}
		}

		static NOINLINE void HandleAddedAllocations(const std::vector<std::pair<void*, uint32_t>>& addedAllocations, EventLogWriter& eventLogWriter)
		{
			for (const auto& addedAllocation : addedAllocations)
			{
				const auto allocationBase = addedAllocation.first;
				const auto allocationSize = addedAllocation.second;

				// Add to the allocation list.
				AddAllocationWithSizeToAllocationList(allocationBase, allocationSize);

				// If the new allocation 'should be skipped' we want it in the allocation list, but not in the recording log.
				if (allocationInfos.Get(AllocationBaseToAllocationListIndex(allocationBase)).shouldBeSkipped)
				{
					return;
				}
				
				// Record the allocation. Note that instead of dumping all regions within the allocation to add up the size on the replay side we
				// instead dump the size first and only committed regions since that saves space. We're only interested in committed regions anyway.
				eventLogWriter.AddMemoryAllocationAddedEvent(allocationSize);

				IterateMemRegionHeaders(allocationBase, nullptr, [&allocationBase, &eventLogWriter](const MEMORY_BASIC_INFORMATION& memRegionHeader)
				{
					// TODO Keep a size count, then just return when we exceed the allocationSize so we don't have to do the last syscall
					if (memRegionHeader.AllocationBase != allocationBase)
					{
						return IterateMemRegionHeadersReturnValues::StopIterating;
					}

					if (memRegionHeader.State == MEM_COMMIT)
					{
						// Note that for MemoryRegionAddedEvents following a MemoryAllocationAddedEvent we only care that the regions are committed and
						// whether they're guarded or not, so we can leave out the regionProtection and regionState if we want (since we know it'll be committed).
						// TODO Could split this into an event taking only committed regions to save some log space.
						eventLogWriter.AddMemoryRegionAddedEvent(memRegionHeader.BaseAddress, allocationBase, memRegionHeader.RegionSize, memRegionHeader.Protect, memRegionHeader.State);
					}

					return IterateMemRegionHeadersReturnValues::GoToNextRegion;
				});
			}
		}

		static NOINLINE void CompareMemoryBeforeAndAfterSyscallAndHandleChanges(const void* currentThreadsTebBaseAddr, EventLogWriter& eventLogWriter)
		{
			auto& allocationBasesAfterSyscall = _allocationBasesAfterSyscall;

			// Important!
			allocationBasesAfterSyscall.Reset();

			// -------------------------------------------------------------------------------------

			// This function call:
			// 1) Retrieves all allocation bases that currently exist after the syscall.
			// 2) Retrieves a list of allocations that were added by the syscall.
			// 3) Clears and refills all lists of committed regions.
			//
			// We iterate through all memory regions here so this function must come first. Memory scanning only happens this once per syscall.
			// CommentID='Handling added allocations':
			// We don't want to apply subsequent comparison checks on new allocations, because obviously they don't apply (the allocation is new and was not seen before),
			// so we avoid handling new allocations until last and instead return a reference to a list of the new allocation bases.
			const auto& addedAllocations = RetrieveAddedAllocationsAndUpdateCommittedRegionsLists(allocationBasesAfterSyscall);

			// -------------------------------------------------------------------------------------

			// We handle freed allocations first so that subsequent handlers don't have to waste time checking on allocations that were already freed (we remove them from the allocation list).
			HandleFreedAllocations(allocationBasesAfterSyscall, eventLogWriter);

			// -------------------------------------------------------------------------------------

			// Handle modifications to memory pages.
			const auto handleModifiedMemPageFunc = [&eventLogWriter](void* pageAddr)
			{
				eventLogWriter.AddMemoryModifiedEvent(pageAddr, Util::System::PageSize);
			};

			HandleModificationsToWriteWatchedAllocations(handleModifiedMemPageFunc);
			HandleModificationsToNonWriteWatchedAllocations(currentThreadsTebBaseAddr, handleModifiedMemPageFunc);

			// -------------------------------------------------------------------------------------

			// Handle added allocations. Do this step last (see CommentID='Handling added allocations').
			HandleAddedAllocations(addedAllocations, eventLogWriter);

			// Note: We assume allocations were not freed and reallocated, thus we can assume the size is retained.

			// CommentID='Not checksumming regions with page guards': Regions with page guards (even if they contain data) are ignored, because we only want to checksum non-guarded regions.
			// If, somewhere between the time this check was made and before the checksumming happens before the next syscall, a guarded region is accessed
			// and the guard status is lost, we will get an exception (STATUS_GUARD_PAGE_VIOLATION). We can intercept this exception, round down to allocation granularity
			// repeatedly until we find the allocationInfo record (which should exist), and we can then do a NtQueryVirtualMemory on the now non-guarded region and
			// see if it is eligible to be put in the committed-regions list of the allocation. In that case the region will be checksummed alongside the others later.
		}

		// Takes in the register context pre- and post-syscall. Returns a bitmap of which registers were modified in a format which can be passed to EventLogWriter.AddContextModifiedEvent().
		static NOINLINE unsigned char CompareContextBeforeAndAfterSyscall(const SyscallInfo& syscallInfo, const SyscallReturnContext& syscallReturnContext)
		{
			unsigned char result = 0;

			if (syscallReturnContext._eax != syscallInfo.eax)
				BIT_SET(result, EventLogWriter::ContextModifiedEventBitmapRegisterIndices::EAX);
			if (syscallReturnContext._ecx != syscallInfo.ecx)
				BIT_SET(result, EventLogWriter::ContextModifiedEventBitmapRegisterIndices::ECX);
			if (syscallReturnContext._edx != syscallInfo.edx)
				BIT_SET(result, EventLogWriter::ContextModifiedEventBitmapRegisterIndices::EDX);

			return result;
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		static NOINLINE std::pair<unsigned char*, uint32_t> RetrieveStackContents(const SyscallInfo& syscallInfo, const ThreadRecordingInfo& threadRecordingInfo, unsigned char* stackDataContainer)
		{
			const unsigned char* lowestStackAddr = (unsigned char*)syscallInfo.esp;
			const unsigned char* highestStackAddr = (unsigned char*)threadRecordingInfo.threadInfo.teb32->StackBase - 0x4;
			const uint32_t stackSize = highestStackAddr - lowestStackAddr;

			CopyMemory(stackDataContainer, lowestStackAddr, stackSize);
			return std::make_pair(stackDataContainer, stackSize);
		}

		static NOINLINE void CompareStackBeforeAndAfterSyscallAndHandleChanges(EventLogWriter& eventLogWriter, const SyscallInfo& syscallInfo, const std::pair<unsigned char*, uint32_t>& stackContentsBeforeSyscall)
		{
			std::pair<unsigned char*, uint32_t> stackContentsAfterSyscall = std::make_pair((unsigned char*)syscallInfo.esp, stackContentsBeforeSyscall.second);
			eventLogWriter.AddMemoryModifiedEventsFromDifferencesInByteArrays(stackContentsBeforeSyscall, stackContentsAfterSyscall);
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		static __declspec(naked) void OrgSyscallInterfaceBytes()
		{
			// The original syscall interface bytes (WOW64 far jump) will be written here when we hook it.
			// Using a function instead of a normal buffer so we can execute the bytes easily.
			// Also note that a far jump is 7 bytes, not 5.
			__asm
			{
				nop
				nop
				nop
				nop
				nop
				nop
				nop
			}
		}

		// This function issues the original syscall.
		// When we entered the syscall handler we backed up the register context and we now have to restore it to do the original syscall.
		// When we return from the syscall we backup the registers again, because the syscall handler still has stuff it needs to do before
		// we return to the original syscall caller. If we didn't do this step the syscall handler would have to walk on eggshells to not
		// overwrite the syscall result while doing its job, so it's easier to just back it all up temporarily and restore it when we finally
		// leave the syscall handler.
		static __declspec(noinline, naked) void OrgSyscall(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext)
		{
			// WARNING!
			// Avoid using anything but EAX, ECX and EDX in here as per the calling convention,
			// because the caller (compiler) won't backup the other registers, and due to the stack frame removal
			// before the syscall it's not as simple as backing them up on the stack, so it's easier
			// to just not use them at all. The reason the compiler won't back up the registers is
			// because the function is marked as 'naked', so that's our responsibility.
			__asm
			{
				// Prologue.
				push ebp
				mov ebp, esp
				
				// Restore required registers for the syscall as they were when entering the syscall interface originally.
				// Remember that references are just pointers with value semantics that don't apply in assembly, so we have to dereference the pointers.
				mov eax, syscallInfo
				mov ecx, [eax].ecx
				mov edx, [eax].edx
				mov eax, [eax].eax

				// Epilogue.
				mov esp, ebp
				pop ebp

				// Returns on the next line since we issued a call, with NTSTATUS in eax.
				call OrgSyscallInterfaceBytes

				// Return address from last call stays on stack after returning from kernel mode, so need to get rid of it manually.
				add esp, 4

				// Prologue.
				push ebp
				mov ebp, esp

				// Backup EAX, ECX and EDX so it's safe to change them until the syscall handler exits (where they get restored).
				// Note that we can't use any of the other registers (see top comment), and we can't overwrite what's in EAX, ECX and EDX,
				// so we have to backup one of them temporarily.
				push eax

				mov eax, syscallReturnContext
				mov [eax]._ecx, ecx
				mov [eax]._edx, edx
				
				mov ecx, eax // ECX has been backed up now so we're free to overwrite it
				pop eax

				mov [ecx]._eax, eax

				// Epilogue.
				mov esp, ebp
				pop ebp

				ret
			}
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		/* Manual Syscall Handlers */
		// Some syscalls must be specially handled in order for recording to work properly.
		// Other syscalls are handled manually for space and speed reasons, but it's not strictly necessary to do this.

		// TODO Acquire these dynamically, of course. Just disassemble the first instruction at each function to get the index in EAX
		#define SYSCALL_INDEX_NT_ALLOCATE_VIRTUAL_MEMORY 0x15
		#define SYSCALL_INDEX_NT_FREE_VIRTUAL_MEMORY 0x1B
		#define SYSCALL_INDEX_NT_QUERY_VIRTUAL_MEMORY 0x20
		#define SYSCALL_INDEX_NT_TERMINATE_PROCESS 0x29
		#define SYSCALL_INDEX_NT_CONTINUE 0x40
		#define SYSCALL_INDEX_NT_TERMINATE_THREAD 0x50
		#define SYSCALL_INDEX_NT_RAISE_EXCEPTION 0x12F

		// Syscall function signature: HANDLE processHandle, PVOID* baseAddress, ULONG_PTR zeroBits, PSIZE_T regionSize, ULONG allocationType, ULONG protect.
		// Returns whether the allocation type contained MEM_RESERVE.
		static NOINLINE bool OnNtAllocateVirtualMemory(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext)
		{
			DWORD* const syscallStackArgsPtr = (DWORD*)syscallInfo.edx;

			// If allocationType is MEM_RESERVE, add MEM_WRITE_WATCH flag.
			DWORD* pAllocationType = syscallStackArgsPtr + 4;
			const bool allocationTypeContainsMemReserve = (bool)(*pAllocationType & MEM_RESERVE);

			if (allocationTypeContainsMemReserve)
			{
				*pAllocationType |= MEM_WRITE_WATCH;
			}

			// Original syscall.
			OrgSyscall(syscallInfo, syscallReturnContext);

			return allocationTypeContainsMemReserve;
		}

		// Syscall function signature: HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType.
		static NOINLINE void OnNtFreeVirtualMemory(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext)
		{
			// Original syscall.
			OrgSyscall(syscallInfo, syscallReturnContext);
		}

		static NOINLINE void OnNtTerminateThread(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext)
		{
			// IMPORTANT_TODO:
			// There are two options here:
			// - The thread successfully exits.
			// - The thread fails to exit.
			//
			// If the thread succeeded in exiting we need to notify DragoonDll#OnThreadExit first thing.
			// Since we won't return after the syscall (if thread exits itself and not another thread),
			// and we need to know if the syscall actually succeeded, we need to find a way
			// to do this after the fact, maybe with some kind of callback mechanism? If the syscall failed we'll continue on the next line.

			// As NtTerminateThread() is the last place in user mode where the thread operates before exiting
			// we call OnThreadExit() here instead of in, say, DllMain() (with reason=DLL_THREAD_DETACH), or anywhere else,
			// because that would create an unrecorded zone from the point we did OnThreadExit() to the termination syscall.

			__asm int 3;
			__asm int 0xEE;

			// TODO Note allocations/frees that occurred after this syscall.
			// TODO Unregister thread (which should remove it from all lists etc.).

			// TODO If last thread, stop recording. If last thread, yield once so we block and let other
			// possible new scheduled threads we don't know about run. If truly last thread, stop recording.
			// TODO If not last thread, call OnThreadExit(). Don't call it directly since that violates the no-library-interaction rule.
			// Schedule it to be run ASAP after terminating this thread.
			// TODO Is this handled by NtTerminateProcess? The "is last thread" part.

			// TODO Might be another thread than the current thread being terminated, so don't always assume success.

			OrgSyscall(syscallInfo, syscallReturnContext);

			// We're assuming all thread termination requests succeed and won't handle the cases where they don't. Should never reach this line.
			DragoonGlobal::SafeAbort();
		}

		static NOINLINE void OnNtTerminateProcess(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext)
		{
			// NtTerminateThread() may be called for other purposes than terminating the current process.
			// Therefore, only call onProcessExit() if we're sure the process is actually terminating.
			// TODO Might be another process being terminated, so don't always assume success.

			OrgSyscall(syscallInfo, syscallReturnContext);

			DragoonGlobal::SafeAbort();
		}

		static NOINLINE void OnNtContinue(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext)
		{
			// NtContinue is a special snowflake because it doesn't return; the purpose of the operation is to change the thread context
			// and execute from the new context. Therefore we need to enable syscall redirection again, otherwise it'll stay disabled after the call.
			EnableRecordingOfThread(syscallInfo.threadId);

			OrgSyscall(syscallInfo, syscallReturnContext);

			// Let's assume all calls to NtContinue() succeed. In other words, we should never reach this line.
			DragoonGlobal::SafeAbort();
		}

		static NOINLINE void OnNtRaiseException(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext)
		{
			// Syscall never returns, need to re-enable recording.
			// Execution continues at KiUserExceptionDispatcher or the line that caused the previous
			// exception to occur (NtRaiseException is being called from KiUserExceptionDispatcher)?
			EnableRecordingOfThread(syscallInfo.threadId);

			OrgSyscall(syscallInfo, syscallReturnContext);

			DragoonGlobal::SafeAbort();
		}

		static NOINLINE void OnNtQueryVirtualMemory(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext, const ThreadRecordingInfo& threadRecordingInfo)
		{
			/* Example how to handle NtQueryVirtualMemory */
			auto& eventLogWriter = *threadRecordingInfo.eventLogWriter;
			MEMORY_BASIC_INFORMATION* pMemBasicInfoArg = (MEMORY_BASIC_INFORMATION*)*((uint32_t*)syscallInfo.edx + 3);

			OrgSyscall(syscallInfo, syscallReturnContext);

			eventLogWriter.LockForWriting();
			eventLogWriter.DisableMemoryLockCheck();

			// Dump only what we need.
			eventLogWriter.AddSyscallEvent(syscallInfo.eax);
			eventLogWriter.AddMemoryModifiedEvent(pMemBasicInfoArg, sizeof(MEMORY_BASIC_INFORMATION));

			eventLogWriter.EnableMemoryLockCheck();
			eventLogWriter.ReleaseWriteLock();

			// TODO Need to log context too?
		}

		static NOINLINE void OnUnhandledSyscall(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext, ThreadRecordingInfo& threadRecordingInfo)
		{
			// IMPORTANT_TODO For multithreading, see dev notes: "Dealing with memory changes during multithreaded recording".
			// Author's note: These are my private Google Docs notes, sorry. It's just a bunch of details. See the thesis for a general outline.
			auto& memoryLock = GetMemoryLock();
			memoryLock.Acquire();

			const void* currentThreadsTebBaseAddr = threadRecordingInfo.threadInfo.teb32;
			PrepareForMemoryComparison(currentThreadsTebBaseAddr, threadRecordingInfo);

			auto stackContentsBeforeSyscall = RetrieveStackContents(syscallInfo, threadRecordingInfo, threadRecordingInfo.stackContentsContainer);

			OrgSyscall(syscallInfo, syscallReturnContext);

			// Log the syscall as one aggregate event with multiple sub-events.
			// ----------
			auto& eventLogWriter = *threadRecordingInfo.eventLogWriter;
			eventLogWriter.LockForWriting();
			eventLogWriter.AddSyscallEvent(syscallInfo.eax);

			CompareMemoryBeforeAndAfterSyscallAndHandleChanges(currentThreadsTebBaseAddr, eventLogWriter);

			CompareStackBeforeAndAfterSyscallAndHandleChanges(eventLogWriter, syscallInfo, stackContentsBeforeSyscall);

			memoryLock.Release();

			// Context events come last as specified in EventLogWriter's interface.
			CONTEXT ctx;
			ctx.Eax = syscallReturnContext._eax;
			ctx.Ecx = syscallReturnContext._ecx;
			ctx.Edx = syscallReturnContext._edx;
			eventLogWriter.AddContextModifiedEvent(CompareContextBeforeAndAfterSyscall(syscallInfo, syscallReturnContext), ctx);

			eventLogWriter.ReleaseWriteLock();
			// ----------
		}

		static NOINLINE void RecordSyscall(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext, ThreadRecordingInfo& threadRecordingInfo)
		{
			// We'll become acquainted with recursion if we try to record syscalls while already recording a syscall.
			DisableRecordingOfThread(syscallInfo.threadId);

			// These syscalls need special handling for the recorder, so be careful not to confuse them with syscalls being manually handled just for speed reasons.
			if (syscallInfo.eax == SYSCALL_INDEX_NT_ALLOCATE_VIRTUAL_MEMORY)
			{
				auto& memoryLock = GetMemoryLock();
				memoryLock.Acquire();

				const bool allocationTypeContainedMemReserve = OnNtAllocateVirtualMemory(syscallInfo, syscallReturnContext);

				// If allocation was successful and it was a new allocation (not commit), add it to the allocation list.
				if (Util::Windows::IsNtSuccess(syscallReturnContext._eax))
				{
					if (allocationTypeContainedMemReserve)
					{
						void* allocatedAllocationBase = (void*)**((DWORD**)syscallInfo.edx + 1);
						AddAllocationToAllocationList(allocatedAllocationBase);
					}
				}

				memoryLock.Release();
			}
			else if (syscallInfo.eax == SYSCALL_INDEX_NT_FREE_VIRTUAL_MEMORY)
			{
				auto& memoryLock = GetMemoryLock();
				memoryLock.Acquire();

				OnNtFreeVirtualMemory(syscallInfo, syscallReturnContext);

				// If freeing was successful (full release, not decommit), remove the allocation from the allocation list.
				if (Util::Windows::IsNtSuccess(syscallReturnContext._eax))
				{
					const bool freeTypeWasMemRelease = *((DWORD*)syscallInfo.edx + 3) & MEM_RELEASE;
					if (freeTypeWasMemRelease)
					{
						void* freedAllocationBase = (void*)**((DWORD**)syscallInfo.edx + 1);
						RemoveAllocationFromAllocationList(freedAllocationBase);
					}
				}

				memoryLock.Release();
			}
			else if (syscallInfo.eax == SYSCALL_INDEX_NT_TERMINATE_THREAD)
			{
				OnNtTerminateThread(syscallInfo, syscallReturnContext);
			}
			else if (syscallInfo.eax == SYSCALL_INDEX_NT_TERMINATE_PROCESS)
			{
				OnNtTerminateProcess(syscallInfo, syscallReturnContext);
			}
			else if (syscallInfo.eax == SYSCALL_INDEX_NT_CONTINUE)
			{
				OnNtContinue(syscallInfo, syscallReturnContext);
			}
			else if (syscallInfo.eax == SYSCALL_INDEX_NT_RAISE_EXCEPTION)
			{
				OnNtRaiseException(syscallInfo, syscallReturnContext);
			}
			// These syscalls are handled manually for speed and space reasons.
			else if (syscallInfo.eax == SYSCALL_INDEX_NT_QUERY_VIRTUAL_MEMORY)
			{
				OnNtQueryVirtualMemory(syscallInfo, syscallReturnContext, threadRecordingInfo);
			}
			// All other syscalls get handled automatically at a higher speed and space cost.
			else
			{
				OnUnhandledSyscall(syscallInfo, syscallReturnContext, threadRecordingInfo);
			}

			// Re-enable recording.
			EnableRecordingOfThread(syscallInfo.threadId);
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		// TODO Remove?
		static uint32_t numSyscallsCountSinceRecordingStart = 0xFFFFFFFF;

		static NOINLINE void _DoNotRecordSyscall(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext, const bool isThreadBeingRecorded)
		{
			// TODO Do we still need this?
			// Reset the do-not-record-next-syscall singleshoot if the thread was meant to be recorded but wasn't.
			if (isThreadBeingRecorded)
			{
				ThreadRecordingInfo& threadRecordingInfo = GetThreadRecordingInfo(syscallInfo.threadId);
				recordingInfo.fpResetDoNotRecordNextSyscallSingleshoot(threadRecordingInfo, syscallInfo.threadId);
			}

			// Even if we're not recording we still need to enforce write watching.
			if (syscallInfo.eax == SYSCALL_INDEX_NT_ALLOCATE_VIRTUAL_MEMORY)
			{
				OnNtAllocateVirtualMemory(syscallInfo, syscallReturnContext);
			}
			else if (syscallInfo.eax == SYSCALL_INDEX_NT_FREE_VIRTUAL_MEMORY)
			{
				OnNtFreeVirtualMemory(syscallInfo, syscallReturnContext);
			}
			else
			{
				OrgSyscall(syscallInfo, syscallReturnContext);
			}
		}

		static NOINLINE void HandleSyscall(const SyscallInfo& syscallInfo, SyscallReturnContext& syscallReturnContext)
		{
			// All threads get intercepted in order for Dragoon to monitor allocation changes.
			//
			// Only threads that have been registered for recording get recorded, however.
			// It is possible for a thread to temporarily disable recording without unregistering.
			const bool isThreadBeingRecorded = IsThreadBeingRecorded(syscallInfo.threadId);

			if (isThreadBeingRecorded)
			{
				ThreadRecordingInfo& threadRecordingInfo = GetThreadRecordingInfo(syscallInfo.threadId);

				if (!recordingInfo.fpShouldNextSyscallNotBeRecorded(threadRecordingInfo, syscallInfo.threadId))
				{
					return RecordSyscall(syscallInfo, syscallReturnContext, threadRecordingInfo);
				}
			}
			else
			{
				return _DoNotRecordSyscall(syscallInfo, syscallReturnContext, isThreadBeingRecorded);
			}
		}

		static __declspec(noinline, naked) NTSTATUS OnSyscall()
		{
			// Warning!
			// Until this function returns it is dangerous to use functionality that assumes there does not exist a syscall hook.
			// For example, if locks are being held that means if we attempt to re-enter a function that relies on said locks there are going to be problems.
			// This is just one example of many. Even though libraries tend to be thread safe they most likely are not re-entrant, so play it safe.
			// Use direct syscalls only.

			// Prologue.
			__asm
			{
				push ebp
				mov ebp, esp
				sub esp, __LOCAL_SIZE
			}

			{
				// Thread-local register backup to uphold the syscall contract (all GPR but EAX, ECX, EDX, EFLAGS must be backed up).
				// EBP and ESP are taken care of automatically by the stack frame mechanism and can be ignored. We do store ESP for utility purposes, however.
				// EFLAGS can be ignored. FPU/MMX, SSE and AVX are preserved by the kernel and can be ignored.
				SyscallInfo syscallInfo;
				__asm
				{
					mov syscallInfo.esp, esp

					mov syscallInfo.eax, eax
					mov syscallInfo.ecx, ecx
					mov syscallInfo.edx, edx

					mov syscallInfo.ebx, ebx
					mov syscallInfo.esi, esi
					mov syscallInfo.edi, edi
				}

				syscallInfo.threadId = GetCurrentThreadId();

				// Retrieve the original ESP as it was when entering the syscall handler by ignoring stack pushes made by the syscall handler.
				__asm
				{
					add syscallInfo.esp, 0x4
					add syscallInfo.esp, __LOCAL_SIZE;
				}

				// Handle the syscall.
				SyscallReturnContext syscallReturnContext;
				HandleSyscall(syscallInfo, syscallReturnContext);

				// Restore the context.
				__asm
				{
					// EAX, ECX and EDX are restored to what they were after the syscall was performed.
					mov eax, syscallReturnContext._eax
					mov ecx, syscallReturnContext._ecx
					mov edx, syscallReturnContext._edx
					
					// EBX, ESI and EDI are restored to what they were when entering the syscall handler.
					mov ebx, syscallInfo.ebx
					mov esi, syscallInfo.esi
					mov edi, syscallInfo.edi
				}
			}

			// Epilogue.
			__asm
			{
				mov esp, ebp
				pop ebp
			}

			// Returning from WOW64 takes us back to the syscall handler. Normally it would go back to the Native API which pops off the return address.
			// As such we shouldn't return normally (which includes popping, and then the user code will do another pop and thus crash shortly after),
			// but instead use a little trick and push the return address on the stack one more time. Our ret instruction will pop it off and return
			// to the proper address, and the stack will look like the user code expects it to and the user code can then do its own cleanup.
			__asm
			{
				push [esp]
				ret
			}
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		static NOINLINE void InstallSyscallHook(const Util::Process& process)
		{
			void* syscallInterfaceAddr = (void*)__readfsdword(0xC0);
			const DWORD numOrgSyscallBytes = 7; // Note that it's 7 bytes, not 5, it's a -far- jmp.

			// Hook the syscall interface and redirect it to OnSyscall() (not enabled yet).
			// Also note that it is permanent, ie. it is not uninstalled until program shutdown. The reason for this is
			// that even if recording is not active we still would like to force write watching on memory allocations (among other things).
			syscallInterfaceHook = new Util::Hook(
				process.GetHandle(),
				syscallInterfaceAddr,
				numOrgSyscallBytes,
				OnSyscall,
				Util::Hook::HookType::HOOK_JMP
			);

			// Move the original syscall interface bytes to the buffer in the function at &OrgSyscallInterfaceBytes().
			Util::MemoryRegion(process.GetHandle(), OrgSyscallInterfaceBytes, syscallInterfaceHook->GetOriginalBytes().size())
				.WriteData(syscallInterfaceHook->GetOriginalBytes().data(), syscallInterfaceHook->GetOriginalBytes().size());

			syscallInterfaceHook->Enable();
		}

		/*
		* This function attempts to find the allocation base of The Probed Region, a region which always gets probed in kernel mode, apparently, because
		* GetWriteWatch always returns pages from this region, but none of those pages were actually modified during the kernel time (unless the modifications were reverted).
		* Note that The Probed Region does not have a fixed size, but it's usually around 0x29000 to 0x2B0000-ish in size.
		*
		* Upon further inspection it appears this may be the 64-bit heap and WOW64 uses it; the syscall enters kernel mode
		* and spots the change made by WOW64, then WOW64 reverts the change before returning to the Dragoon syscall handler.
		*/
		static NOINLINE MEMORY_BASIC_INFORMATION RetrieveProbedRegionMemRegionHeader()
		{
			MEMORY_BASIC_INFORMATION _probedRegionMemRegionHeader;
			ZeroMemory(&_probedRegionMemRegionHeader, sizeof(_probedRegionMemRegionHeader));

			for (const auto& memRegionHeader : process->GetMemoryRegionHeaders())
			{
				// Skip NULL region.
				if (memRegionHeader.AllocationBase == NULL)
				{
					continue;
				}

				// Reset write watching.
				NTSTATUS status = fpNtResetWriteWatch(process->GetHandle().GetValue(), memRegionHeader.AllocationBase, memRegionHeader.RegionSize);

				if (!Util::Windows::IsNtSuccess(status))
				{
					// If error was STATUS_INVALID_PARAMETER_1 it means the allocation isn't write watched.
					// In this case that means it's not the region we're looking for, so we try the next region. If it's another error code, we exit.
					if (status == 0xC00000EF)
					{
						continue;
					}
					else
					{
						UTIL_THROW_WIN32("NtResetWriteWatch failed");
					}
				}

				// Perform a basic syscall just to probe the region (it's actually NtGetWriteWatch internally in the
				// syscall handler that probes the region, but this is an easy way to get there).
				MEMORY_BASIC_INFORMATION memBasicInfo;
				status = fpNtQueryVirtualMemory(process->GetHandle().GetValue(), memRegionHeader.AllocationBase, Util::Windows::MemoryBasicInformation, &memBasicInfo, sizeof(memBasicInfo), NULL);
				UTIL_ASSERT(Util::Windows::IsNtSuccess(status));

				// Retrieve written (or in this case "probed") pages.
				PVOID writtenPageAddrs[1024 * 10];
				ULONG_PTR numWrittenPageAddrs = sizeof(writtenPageAddrs) / sizeof(PVOID);
				ULONG granularity = UTIL_SYSTEM_PAGE_SIZE;

				status = fpNtGetWriteWatch(process->GetHandle().GetValue(), 0, memRegionHeader.AllocationBase, memRegionHeader.RegionSize, (PVOID*)&writtenPageAddrs, &numWrittenPageAddrs, &granularity);
				UTIL_ASSERT(Util::Windows::IsNtSuccess(status));

				// If it's the correct region (The Probed Region), the pages claimed by GetWriteWatch to have been written should be:
				// RegionBase, RegionBase+0x3000...RegionBase+(0x3000+0x14000), RegionBase+0x28000 --->
				// ---> (the last page in the region. CORRECTION: It's actually the last page before the RESERVED part of the region, so technically it's not the last page).
				bool isProbedRegion = false;

				for (uint32_t i = 0; i < numWrittenPageAddrs; i++)
				{
					auto& writtenPageAddr = writtenPageAddrs[i];

					if (i == 0 && writtenPageAddr != memRegionHeader.AllocationBase)
					{
						break;
					}

					if (i == 1 && writtenPageAddr != ((unsigned char*)memRegionHeader.AllocationBase + 0x3000))
					{
						break;
					}

					if (i >= 2 && i <= 21)
					{
						const uint32_t currIndex = i - 2;
						if (writtenPageAddr != ((unsigned char*)memRegionHeader.AllocationBase + 0x3000) + (0x1000 * currIndex))
						{
							break;
						}
					}

					if (i == 22 && writtenPageAddr != ((unsigned char*)memRegionHeader.AllocationBase + 0x28000))
					{
						break;
					}

					// If we got this far it must mean the region was The Probed Region.
					isProbedRegion = true;
				}

				// Did we find The Probed Region?
				if (isProbedRegion)
				{
					_probedRegionMemRegionHeader = memRegionHeader;
					break;
				}
				else
				{
					continue;
				}
			}

			// Should have found The Probed Region. Checking for zero since we zeroed out the struct earlier and the allocation base can't be NULL since that allocation is off limits.
			UTIL_ASSERT((bool)(_probedRegionMemRegionHeader.BaseAddress != 0));

			return _probedRegionMemRegionHeader;
		}

		// The Locale region contains a list of languages, so we'll look for a region of size 0x67000 that is read-only and contains 'Hungarian' (random pick) in Unicode.
		static NOINLINE MEMORY_BASIC_INFORMATION RetrieveLocaleRegionMemRegionHeader()
		{
			MEMORY_BASIC_INFORMATION _localeRegionMemRegionHeader;
			ZeroMemory(&_localeRegionMemRegionHeader, sizeof(_localeRegionMemRegionHeader));

			IterateMemRegionHeaders(nullptr, nullptr, [&_localeRegionMemRegionHeader](const MEMORY_BASIC_INFORMATION& memRegionHeader)
			{
				if (memRegionHeader.RegionSize == 0x67000 && memRegionHeader.Protect == PAGE_READONLY)
				{
					char strHungarian[] = { 0x48, 0x00, 0x75, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x61, 0x00, 0x72, 0x00, 0x69, 0x00, 0x61, 0x00, 0x6E, 0x00 };

					std::string needle(strHungarian, sizeof(strHungarian));
					std::string haystack((char*)memRegionHeader.AllocationBase, memRegionHeader.RegionSize);

					if (haystack.find(needle) != std::string::npos)
					{
						_localeRegionMemRegionHeader = memRegionHeader;
						return IterateMemRegionHeadersReturnValues::StopIterating;
					}
				}

				return IterateMemRegionHeadersReturnValues::GoToNextRegion;
			});

			// Should have found the Locale region. Checking against zero since we zeroed out the struct and we know the allocation base can't be NULL.
			UTIL_ASSERT(_localeRegionMemRegionHeader.BaseAddress != 0);

			return _localeRegionMemRegionHeader;
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		void Init(Util::Process* _process, Util::Module* _dragoonDll, Util::NativeMemoryAllocator* _nativeAllocator, const RecordingInfo& _recordingInfo)
		{
			process = _process;
			dragoonDll = _dragoonDll;
			nativeAllocator = _nativeAllocator;
			recordingInfo = _recordingInfo;

			// Pre-allocate. It's safe to assume no more than 32 allocations will ever be added by a syscall.
			_addedAllocations.reserve(32);

			InitPageChecksumsMemoryPool();

			// Make sure some syscall function pointers are cached, because apparently the Util::Windows::NativeApi uses malloc(), which performs library interaction.
			// We certainly don't want any of that in the middle of a syscall, so we force caching here.
			// TODO Just fix Util::Windows::NativeApi to not incur malloc() in the first place! But this should be safe for now since the lib-interaction happens pre-snapshot.
			fpNtQueryVirtualMemory = (Util::Windows::NativeApi::NtQueryVirtualMemory)Util::Windows::NativeApi::GetNtdllFuncPtr("NtQueryVirtualMemory");
			fpNtResetWriteWatch = (Util::Windows::NativeApi::NtResetWriteWatch)Util::Windows::NativeApi::GetNtdllFuncPtr("NtResetWriteWatch");
			fpNtGetWriteWatch = (Util::Windows::NativeApi::NtGetWriteWatch)Util::Windows::NativeApi::GetNtdllFuncPtr("NtGetWriteWatch");

			Util::Windows::NativeApi::GetNtdllFuncPtr("NtProtectVirtualMemory"); // TODO Find out what uses this, may be inside a function call that isn't obvious

			// We need to install the syscall handler here because we have to hook NtAllocateVirtualMemory to enable write watching whether we're recording or not.
			// Must this step be done after creating the record handler? Because if the record handler exists in the custom new_delete.cpp it'll start enabling/disabling syscall redirection.
			// If the syscall handler has been installed too early we may be getting recursion when doing allocator->Malloc() which is the problem we were trying to solve in the first place.
			InstallSyscallHook(*process);

			probedRegionMemRegionHeader = RetrieveProbedRegionMemRegionHeader();
			localeRegionMemRegionHeader = RetrieveLocaleRegionMemRegionHeader();
		}

		void Terminate()
		{
			// TODO Undo everything done in Init().
			syscallInterfaceHook->Disable();
		}

		void StartRecording(const ThreadInfo& threadInfoOfThreadStartingRecording)
		{
			PopulateAllocationList(threadInfoOfThreadStartingRecording);
		}

		void StopRecording()
		{
			ClearAllocationList();
		}

		void ResetSyscallCounterSinceRecordingStart()
		{
			numSyscallsCountSinceRecordingStart = 0;
		}
	}
}