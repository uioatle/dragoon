#pragma once

#include "DragoonGlobal\common.h"
#include "DragoonGlobal\events.h"

#include "lib\Util\include\common.h"
#include "lib\Util\include\lock.h"
#include "lib\Util\include\smart_handle.h"
#include "lib\Util\include\windefs.h"

#include <cstdint>
#include <memory>

namespace Dragoon
{
	/*
	Note: Library interaction is banned within this class and all of its interactions.
	TODO Seems there are some WinAPI functions being called, though. May be fine depending on the operation type but investigate regardless.
	*/
	class EventLogWriter
	{
	public:
		EventLogWriter(const Util::Lock& memoryLock, Util::ThreadId threadId);
		~EventLogWriter();

		void Flush();

		void LockForWriting();
		void ReleaseWriteLock();

		void EnableMemoryLockCheck();
		void DisableMemoryLockCheck();

		/*
		 * Aggregate events.
		 */
		void AddSyscallEvent(uint16_t syscallIndex);
		void AddExceptionEvent(const CONTEXT& ctxOfInstrRaisingException);
		void AddMemoryAllocationAddedEvent(uint32_t size);

		/*
		 * Sub-events.
		 *
		 * Method calls that append sub-events should be made in the order they appear in the header here to ensure the least implementation complexity when processing them in order later.
		 * For example, context modification events should always come last so they can be applied immediately.
		 *
		 * Additionally, memory events that dump memory should verify that the memory lock has been locked before proceeding. Therefore a lock argument is required so we don't forget to check.
		 */
		void AddMemoryRegionAddedEvent(const void* baseAddr, const void* allocationBase, uint32_t regionSize, uint32_t regionProtection, uint32_t regionState);
		void AddMemoryAllocationRemovedEvent(const void* allocationBase);
		void AddMemoryModifiedEvent(const void* addr, uint32_t size);
		void AddMemoryModifiedEventsFromDifferencesInByteArrays(const std::pair<unsigned char*, uint32_t>, const std::pair<unsigned char*, uint32_t>);

		void AddRdtscEvent(uint32_t eax, uint32_t edx);

		// Function takes a bitmap of which registers are included in the dump.
		enum ContextModifiedEventBitmapRegisterIndices : unsigned char
		{
			EAX = 0,
			ECX = 1,
			EDX = 2
		};
		void AddContextModifiedEvent(unsigned char registersToDumpBitmap, const CONTEXT& context);
	private:
		Util::Windows::NativeApi::NtWriteFile fpNtWriteFile;

		// Const to ensure we can check the lock but never try to take it.
		const Util::Lock& memoryLock;
		bool performMemoryLockCheck = true;

		/*
		 * To log thread switches you need to either write the event to the current thread's log, or write the event to the thread being switched to's log.
		 * The former requires locking in case the current thread is already writing an event into its log and another thread that is being switched to attempts to
		 * log the thread switch event. In the latter case some kind of timing scheme is needed, so that you know when to switch between log files. This probably
		 * requires sorting to get timestamps aligned.
		 *
		 * Warning! Do not write to log file without locking it explicitly first. Lock on aggregate events only, since sub-events mean nothing on their own.
		 */
		std::unique_ptr<Util::Lock> writeLock;
		std::unique_ptr<Util::SmartHandle> hLogFile;

		unsigned char logBuffer[DRAGOON_GLOBAL_EVENT_LOG_WRITER_BUFFER_SIZE];
		uint32_t currentLogBufferSize = 0;

		Util::SmartHandle* OpenEventLogFile(const Util::ThreadId threadId);

		void Append(unsigned char* data, uint32_t dataSize);
		void AppendEventCode(DragoonGlobal::Events::EventCodes eventCode);

		void VerifyMemoryLockHasBeenLocked();
	};
}