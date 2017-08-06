#pragma once

#include "common.h"
#include "smart_handle.h"
#include "memory_region.h"
#include "windefs.h"
#include <vector>
#include <memory>
#include <Windows.h>

namespace Util
{
	class Thread
	{
	public:
		Thread(ThreadId threadId, ProcessId processId);
		Thread(Thread&& other);
		Thread& operator=(Thread&& other);

		ThreadId GetId() const;
		ProcessId GetProcessId() const;
		const SmartHandle& GetHandle();

		NT_TIB* GetTEB32();
		//NT_TIB ReadTEB();
		void WriteTEB(const NT_TIB& newTeb);

		bool IsSuspended();
		CONTEXT Suspend(DWORD contextFlagsToReturn = CONTEXT_CONTROL);
		void Resume();
		void ForceResume();

		void SetContext(const CONTEXT& newContext);
		void* ChangeEip(void* newEip);
		//void ChangeStack(void* newStackBase, DWORD newStackSize = 1024 * 1024);

		void Terminate(DWORD exitCode, bool waitUntilTerminated = true);
		void WaitFor();
		DWORD GetExitCode();

		void PinToProcessors(const std::vector<unsigned char>& processorIds);

		static Thread CreateRemote(const SmartHandle& hProcess, ProcessId processId, void* startAddress, void* startParameter, bool waitForThreadToExit = true);
	private:
		ThreadId id;
		ProcessId processId;
		std::unique_ptr<SmartHandle> _pHandle;

		// TODO Needs a proper start value. Can't just set it to 0, what if the thread started suspended etc.?
		// Also can't be 0xFFFFFFFF, because APIs return -1 on error
		volatile DWORD suspendCount = 0x7FFFFFFF;

		Util::Windows::THREAD_BASIC_INFORMATION GetThreadBasicInformation();
		void PerformMove(Thread& other);
	};
}