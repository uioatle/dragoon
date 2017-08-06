#pragma once

#include "smart_handle.h"
#include "windefs.h"
#include "lock.h"
#include "fast_bitset.h"

#include <cstdint>
#include <bitset>
#include <Windows.h>

namespace Util
{
	class NativeMemoryAllocator
	{
	public:
		static const uint32_t AllocationGranularity;

		NativeMemoryAllocator(const SmartHandle& hProcess);

		void* Malloc(uint32_t size);
		bool Free(void* addr);

		bool WasAllocationBaseAllocatedByThisAllocator(void* allocationBase);
	private:
		// Make sure this is aligned.
		struct Block
		{
			uint32_t magic;
			uint32_t size;
			bool isFree;

			Block* prev;
			Block* next;
		};

		Lock allocationLock;
		Lock allocationBasesAllocatedByThisAllocatorBitmapLock;

		const SmartHandle& hProcess;
		Windows::NativeApi::NtAllocateVirtualMemory fpNtAllocateVirtualMemory;
		Windows::NativeApi::NtFreeVirtualMemory fpNtFreeVirtualMemory;

		Block* blockListHead = NULL;
		Block* blockListTail = NULL;

		// Because we cannot use a map due to its internal dynamic memory allocation (this class is meant to avoid that in the first place),
		// we are left with few options. We could use a vector, but that is O(n) iteration time. We could pre-fill a map with every possible
		// combination to get O(1) lookup, but that's going to cost in space. Therefore we instead use the next best thing: a bitmap.
		//
		// 2 GB address space, granularity of each allocation is 0x10000 (VirtualAlloc always allocates at this granularity).
		// That is (1024 * 1024 * 1024 * 2) / 0x10000 = 32768d allocation bases possible. If every allocation base is a bit,
		// we need 0x1000 bytes (one page) to store the whole bitmap.
		FastBitset<32768> allocationBasesAllocatedByThisAllocator;

		Block* GetNextFreeBlock(uint32_t size);
		Block* GetNextFreeBlockFromBlockList(uint32_t size);

		Block* AllocateBlock(uint32_t size);
		void SetUpBlock(Block* block, uint32_t size);
		void InsertBlockIntoBlockList(Block* block);

		void SplitBlock(Block* block, uint32_t requestedSize);
		void MergeWithAdjacentFreeBlocks(Block* block);

		void AddAllocationBaseToAllocationBitmap(void* allocationBase);
	};
}