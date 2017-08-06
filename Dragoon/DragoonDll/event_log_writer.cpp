#include "event_log_writer.h"

#include "DragoonGlobal\common.h"

#include "lib\Util\include\system.h"

#include <sstream>

namespace Dragoon
{
	EventLogWriter::EventLogWriter(const Util::Lock& memoryLock, const Util::ThreadId threadId) :
		memoryLock(memoryLock), writeLock(std::unique_ptr<Util::Lock>(new Util::Lock())), hLogFile(std::unique_ptr<Util::SmartHandle>(OpenEventLogFile(threadId)))
	{
		Util::Windows::NativeApi::Init();
		fpNtWriteFile = (Util::Windows::NativeApi::NtWriteFile)Util::Windows::NativeApi::GetNtdllFuncPtr("NtWriteFile");
	}

	EventLogWriter::~EventLogWriter()
	{
		Flush();
	}

	NOINLINE void EventLogWriter::Append(unsigned char* data, const uint32_t dataSize)
	{
		if (!writeLock->IsLocked())
		{
			DragoonGlobal::SafeAbort();
		}

		// The data is dumped in chunks fitting in the buffer, then the buffer is flushed when full and the cycle repeats from the start of the buffer.
		uint32_t totalSizeLeftToCopy = dataSize;

		while (totalSizeLeftToCopy > 0)
		{
			const uint32_t numBytesOfBufferSpaceAvailable = sizeof(logBuffer) - currentLogBufferSize;
			const uint32_t numBytesToCopy = totalSizeLeftToCopy < numBytesOfBufferSpaceAvailable ? totalSizeLeftToCopy : numBytesOfBufferSpaceAvailable;
			const bool copyOperationWillNeedToFlushAfterwards = numBytesToCopy == numBytesOfBufferSpaceAvailable;

			CopyMemory(&logBuffer[currentLogBufferSize], data, numBytesToCopy);

			data += numBytesToCopy;
			totalSizeLeftToCopy -= numBytesToCopy;
			currentLogBufferSize += numBytesToCopy;

			if (copyOperationWillNeedToFlushAfterwards)
			{
				Flush();
			}
		}
	}

	inline void EventLogWriter::AppendEventCode(const DragoonGlobal::Events::EventCodes eventCode)
	{
		Append((unsigned char*)&eventCode, sizeof(eventCode));
	}

	NOINLINE void EventLogWriter::VerifyMemoryLockHasBeenLocked()
	{
		if (!performMemoryLockCheck)
		{
			return;
		}

		if (!memoryLock.IsLocked())
		{
			// Memory lock needs to be locked prior to adding a memory event.
			DragoonGlobal::SafeAbort();
		}
	}

	NOINLINE void EventLogWriter::Flush()
	{
		if (currentLogBufferSize == 0)
		{
			return;
		}

		// Using direct syscalls to avoid library interaction (as usual).
		Util::Windows::IO_STATUS_BLOCK iosb;
		const NTSTATUS status = fpNtWriteFile(hLogFile->GetValue(), NULL, NULL, NULL, &iosb, &logBuffer, currentLogBufferSize, NULL, NULL);

		if (!Util::Windows::IsNtSuccess(status))
		{
			DragoonGlobal::SafeAbort();
		}

		// Reset the size counter.
		currentLogBufferSize = 0;
	}

	void EventLogWriter::LockForWriting()
	{
		writeLock->Acquire();
	}

	void EventLogWriter::ReleaseWriteLock()
	{
		writeLock->Release();
	}

	void EventLogWriter::EnableMemoryLockCheck()
	{
		performMemoryLockCheck = true;
	}

	void EventLogWriter::DisableMemoryLockCheck()
	{
		performMemoryLockCheck = false;
	}

	/*
	 * Aggregate events.
	 */
	NOINLINE void EventLogWriter::AddSyscallEvent(const uint16_t syscallIndex)
	{
		AppendEventCode(DragoonGlobal::Events::EventCodes::SyscallEvent);
		Append((unsigned char*)&syscallIndex, sizeof(syscallIndex));
	}

	NOINLINE void EventLogWriter::AddExceptionEvent(const CONTEXT& ctxOfInstrRaisingException)
	{
		__asm int 3;
		__asm int 1;

		// TODO Add this
		//AppendEventCode(DragoonGlobal::Events::EventCodes::ExceptionEvent);
		//Append((unsigned char*)&ctxOfInstrRaisingException, sizeof(ctxOfInstrRaisingException)); // TODO Dumping correct variable here?
	}

	NOINLINE void EventLogWriter::AddMemoryAllocationAddedEvent(const uint32_t size)
	{
		VerifyMemoryLockHasBeenLocked();

		AppendEventCode(DragoonGlobal::Events::EventCodes::MemoryAllocationAddedEvent);
		Append((unsigned char*)&size, sizeof(size));
	}

	/*
	 * Sub-events.
	 */
	NOINLINE void EventLogWriter::AddMemoryRegionAddedEvent(const void* baseAddr, const void* allocationBase, const uint32_t regionSize, const uint32_t regionProtection, const uint32_t regionState)
	{
		VerifyMemoryLockHasBeenLocked();

		AppendEventCode(DragoonGlobal::Events::EventCodes::MemoryRegionAddedEvent);
		Append((unsigned char*)&baseAddr, sizeof(baseAddr));
		Append((unsigned char*)&allocationBase, sizeof(allocationBase));
		Append((unsigned char*)&regionSize, sizeof(regionSize));
		Append((unsigned char*)&regionProtection, sizeof(regionProtection));
		Append((unsigned char*)&regionState, sizeof(regionState));

		// If the region has data in it, dump that too.
		if (regionState == MEM_COMMIT && regionSize > 0)
		{
			// If the region is guarded we temporarily remove the guard.
			const bool regionIsGuarded = regionProtection & PAGE_GUARD;
			if (regionIsGuarded)
			{
				// TODO Remove guard
			}

			Append((unsigned char*)baseAddr, regionSize);

			if (regionIsGuarded)
			{
				// TODO Restore guard
			}
		}
	}

	NOINLINE void EventLogWriter::AddMemoryAllocationRemovedEvent(const void* allocationBase)
	{
		VerifyMemoryLockHasBeenLocked(); // TODO Is this necessary when reporting a free event?

		AppendEventCode(DragoonGlobal::Events::EventCodes::MemoryAllocationRemovedEvent);
		Append((unsigned char*)&allocationBase, sizeof(allocationBase));
	}

	NOINLINE void EventLogWriter::AddMemoryModifiedEvent(const void* addr, const uint32_t size)
	{
		if (size == 0)
		{
			DragoonGlobal::SafeAbort();
		}

		VerifyMemoryLockHasBeenLocked();
		
		AppendEventCode(DragoonGlobal::Events::EventCodes::MemoryModifiedEvent);
		Append((unsigned char*)&addr, sizeof(addr));
		Append((unsigned char*)&size, sizeof(size));
		
		// Dump the data.
		Append((unsigned char*)addr, size);
	}

	// Takes two arrays and dumps every sub-array that is different in the two arrays as MemoryModifiedEvents.
	NOINLINE void EventLogWriter::AddMemoryModifiedEventsFromDifferencesInByteArrays(const std::pair<unsigned char*, uint32_t> array1, const std::pair<unsigned char*, uint32_t> array2)
	{
		const auto pArray1Base = array1.first;
		const auto pArray2Base = array2.first;
		const auto array1Size = array1.second;
		const auto array2Size = array2.second;

		if (array1Size == 0)
		{
			DragoonGlobal::SafeAbort();
		}

		if (array1Size != array2Size)
		{
			DragoonGlobal::SafeAbort();
		}

		// Every byte of array1 is compared to the same index byte of array2.
		// Sub-arrays are created consisting of a range of non-matching bytes in both arrays. The sub-array stops once matching bytes are found.
		uint32_t subArraySize = 0;
		auto pArray2 = pArray2Base;

		for (uint32_t i = 0; i < array1Size; ++i)
		{
			// Compare bytes in both arrays at the same index. Note that base pointers are compared, not the temporary pointer for array2.
			if (pArray1Base[i] != pArray2Base[i])
			{
				++subArraySize;
				continue;
			}

			// No sub-array found?
			if (subArraySize == 0)
			{
				++pArray2;
				continue;
			}

			// TODO Find a way so that single bytes are not dumped individually, thus causing too much additional metadata in the log.
			//// If the sub-array is less than 4 bytes, set its size to 4 bytes and reposition the pointer to the start of the current 4-byte alignment so that 4 bytes can be dumped at a time.
			//if (subArraySize < 4)
			//{
			//	if (!DragoonGlobal::IsAlignedTo4Bytes((uint32_t)pArray2))
			//	{
			//		pArray2 = (unsigned char*)DragoonGlobal::AlignTo4Bytes((uint32_t)pArray2);
			//	}

			//	subArraySize = 4;
			//}

			// Dump the sub-array.
			AddMemoryModifiedEvent(pArray2, subArraySize);

			// Start over after the current sub-array.
			pArray2 += subArraySize + 1;
			subArraySize = 0;
		}

		// If the loop was exited but a sub-array was in the making, dump it.
		if (subArraySize != 0)
		{
			AddMemoryModifiedEvent(pArray2, subArraySize);
		}
	}

	NOINLINE void EventLogWriter::AddRdtscEvent(const uint32_t eax, const uint32_t edx)
	{
		AppendEventCode(DragoonGlobal::Events::EventCodes::RdtscEvent);
		Append((unsigned char*)&eax, sizeof(eax));
		Append((unsigned char*)&edx, sizeof(edx));
	}

	NOINLINE void EventLogWriter::AddContextModifiedEvent(const unsigned char registersToDumpBitmap, const CONTEXT& context)
	{
		AppendEventCode(DragoonGlobal::Events::EventCodes::ContextModifiedEvent);
		Append((unsigned char*)&registersToDumpBitmap, sizeof(registersToDumpBitmap));

		if (BIT_CHECK(registersToDumpBitmap, ContextModifiedEventBitmapRegisterIndices::EAX))
		{
			Append((unsigned char*)&context.Eax, sizeof(context.Eax));
		}

		if (BIT_CHECK(registersToDumpBitmap, ContextModifiedEventBitmapRegisterIndices::ECX))
		{
			Append((unsigned char*)&context.Ecx, sizeof(context.Ecx));
		}

		if (BIT_CHECK(registersToDumpBitmap, ContextModifiedEventBitmapRegisterIndices::EDX))
		{
			Append((unsigned char*)&context.Edx, sizeof(context.Edx));
		}
	}

	Util::SmartHandle* EventLogWriter::OpenEventLogFile(const Util::ThreadId threadId)
	{
		std::stringstream ss;
		ss << DragoonGlobal::Paths::recordingDir << std::hex << threadId << ".tel";
		const std::string filePath = ss.str();

		// Open existing or create new if does not exist. File handle is closed when its SmartHandle wrapper is deleted (it's deleted when the object is deleted).
		// Note that new threads that share ID with already exited threads of the same ID will write to the same file.
		// This is for convenience both here and in the post-processor.
		return new Util::SmartHandle(
			CreateFileA(filePath.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL),
			INVALID_HANDLE_VALUE
		);
	}
}