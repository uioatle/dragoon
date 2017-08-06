#include "native_memory_allocator.h"
#include "common.h"
#include "system.h"

#include <stdexcept>

namespace Util
{
	const uint32_t NativeMemoryAllocator::AllocationGranularity = System::PageSize * 256; // 1 MB

	__declspec(noinline) NativeMemoryAllocator::NativeMemoryAllocator(const SmartHandle& hProcess) : hProcess(hProcess)
	{
		Windows::NativeApi::Init();
		fpNtAllocateVirtualMemory = (Windows::NativeApi::NtAllocateVirtualMemory)Windows::NativeApi::GetNtdllFuncPtr("NtAllocateVirtualMemory");
		fpNtFreeVirtualMemory = (Windows::NativeApi::NtFreeVirtualMemory)Windows::NativeApi::GetNtdllFuncPtr("NtFreeVirtualMemory");
	}

	__declspec(noinline) void* NativeMemoryAllocator::Malloc(uint32_t size)
	{
		// TODO Round up to 8 bytes here somewhere? For the best alignment? Check Patrick's answer: http://stackoverflow.com/questions/4068046/getting-to-know-size-of-a-reserved-memory-on-the-heap/4068118#4068118

		if (size == 0)
		{
			return NULL;
		}

		size = UTIL_ROUND_UP_TO_4BYTE_ALIGNMENT(size);

		allocationLock.Acquire();

		Block* block = GetNextFreeBlock(size);
		if (!block)
		{
			allocationLock.Release();
			return NULL;
		}

		SplitBlock(block, size);

		block->isFree = false;
		allocationLock.Release();
		return (void*)(block + 1);
	}

	__declspec(noinline) bool NativeMemoryAllocator::Free(void* addr)
	{
		if (!addr)
		{
			return false;
		}

		Block* block = (Block*)((char*)addr - sizeof(Block));

		// Verify it's a block allocated with this allocator.
		if (block->magic != 0xAABBCCDD)
		{
			return false;
		}

		allocationLock.Acquire();

		block->isFree = true;
		MergeWithAdjacentFreeBlocks(block);

		allocationLock.Release();
		return true;
	}

	__declspec(noinline) void NativeMemoryAllocator::AddAllocationBaseToAllocationBitmap(void* allocationBase)
	{
		const uint16_t allocationIndex = (uint32_t)allocationBase / Util::System::AllocationGranularitySize;

		allocationBasesAllocatedByThisAllocatorBitmapLock.Acquire();
		allocationBasesAllocatedByThisAllocator.Set(allocationIndex);
		allocationBasesAllocatedByThisAllocatorBitmapLock.Release();
	}

	__declspec(noinline) bool NativeMemoryAllocator::WasAllocationBaseAllocatedByThisAllocator(void* allocationBase)
	{
		const uint16_t allocationIndex = (uint32_t)allocationBase / Util::System::AllocationGranularitySize;

		allocationBasesAllocatedByThisAllocatorBitmapLock.Acquire();
		const bool isBitSet = allocationBasesAllocatedByThisAllocator.Test(allocationIndex);
		allocationBasesAllocatedByThisAllocatorBitmapLock.Release();

		return isBitSet;
	}

	__declspec(noinline) NativeMemoryAllocator::Block* NativeMemoryAllocator::GetNextFreeBlock(const uint32_t size)
	{
		Block* block = GetNextFreeBlockFromBlockList(size);

		if (!block)
		{
			block = AllocateBlock(size);
		}

		return block;
	}

	__declspec(noinline) NativeMemoryAllocator::Block* NativeMemoryAllocator::GetNextFreeBlockFromBlockList(const uint32_t size)
	{
		Block* current = blockListHead;

		while (current)
		{
			if (current->isFree && current->size >= size)
			{
				return current;
			}

			current = current->next;
		}

		return NULL;
	}

	__declspec(noinline) NativeMemoryAllocator::Block* NativeMemoryAllocator::AllocateBlock(const uint32_t size)
	{
		const uint32_t totalSize = RoundUp(
			sizeof(Block) + size,
			AllocationGranularity
		);

		void* _baseAddr = NULL;
		SIZE_T _size = totalSize;
		const NTSTATUS status = fpNtAllocateVirtualMemory(hProcess.GetValue(), &_baseAddr, 0, &_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if (!Windows::IsNtSuccess(status))
		{
			return NULL;
		}

		Block* block = (Block*)_baseAddr;
		SetUpBlock(block, totalSize - sizeof(Block));

		InsertBlockIntoBlockList(block);

		// BaseAddr == AllocationBase when returned from VirtualAlloc.
		AddAllocationBaseToAllocationBitmap(_baseAddr);

		return block;
	}

	__declspec(noinline) void NativeMemoryAllocator::SetUpBlock(Block* block, const uint32_t size)
	{
		block->magic = 0xAABBCCDD;
		block->size = size;
		block->isFree = true;
	}

	__declspec(noinline) void NativeMemoryAllocator::InsertBlockIntoBlockList(Block* block)
	{
		block->prev = NULL;
		block->next = NULL;

		// First block in the list.
		if (!blockListHead)
		{
			blockListHead = block;
			blockListTail = block;
		}
		// There exists one block in the list.
		else if (blockListHead && blockListTail == blockListHead)
		{
			blockListTail = block;

			blockListHead->next = blockListTail;
			blockListTail->prev = blockListHead;
		}
		// There exist more than one block in the list.
		else
		{
			Block* oldTail = blockListTail;
			blockListTail = block;

			oldTail->next = blockListTail;
			blockListTail->prev = oldTail;
		}
	}

	/*
	Splits a block at the requested size. If there is room left to create a new block with the remaining size, this is done and the new block is linked into the block list.
	*/
	__declspec(noinline) void NativeMemoryAllocator::SplitBlock(Block* block, const uint32_t requestedSize)
	{
		// If we reserve the requested size from the block, will there be room for a header and at least one byte (rounded to alignment) so that a new block can be created from the remaining space?
		const uint32_t blockSizeWithoutRequestedSize = block->size - requestedSize;

		if (blockSizeWithoutRequestedSize < sizeof(Block) + 4)
		{
			// Don't split the block, just leave it as is.
			return;
		}

		// Create a new block at the location past the requested size.
		Block* newBlock = (Block*)((unsigned char*)block + sizeof(Block) + requestedSize);
		SetUpBlock(newBlock, blockSizeWithoutRequestedSize - sizeof(Block));

		// Link the new block into the block list.
		newBlock->next = block->next;

		if (newBlock->next)
		{
			newBlock->next->prev = newBlock;
		}

		block->next = newBlock;
		newBlock->prev = block;

		// Remember to update the size of the old block.
		block->size = requestedSize;
	}

	__declspec(noinline) void NativeMemoryAllocator::MergeWithAdjacentFreeBlocks(Block* block)
	{
		Block* prevBlock = block->prev;
		Block* nextBlock = block->next;

		// Merge with next block?
		if (nextBlock && nextBlock->isFree)
		{
			const bool isNextBlockAdjacent = (Block*)((unsigned char*)block + sizeof(Block) + block->size) == nextBlock;

			if (isNextBlockAdjacent)
			{
				block->size += sizeof(Block) + nextBlock->size;

				block->next = nextBlock->next;

				if (block->next)
				{
					block->next->prev = block;
				}
			}
		}

		// Merge with previous block?
		if (prevBlock && prevBlock->isFree)
		{
			const bool isPrevBlockAdjacent = (Block*)((unsigned char*)prevBlock + sizeof(Block) + prevBlock->size) == block;

			if (isPrevBlockAdjacent)
			{
				prevBlock->size += sizeof(Block) + block->size;

				prevBlock->next = block->next;

				if (prevBlock->next)
				{
					prevBlock->next->prev = prevBlock;
				}
			}
		}
	}
}