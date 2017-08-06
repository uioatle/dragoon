#pragma once

#include "syscall_handler.h"

#include "lib\Util\include\common.h"
#include "lib\Util\include\process.h"
#include "lib\Util\include\trampoline.h"
#include "lib\Util\include\native_memory_allocator.h"
#include "lib\Util\include\module.h"

namespace Dragoon
{
	namespace RecordingHandler
	{
		void Init(Util::Process* process, Util::Module* dragoonDll, Util::NativeMemoryAllocator* nativeAllocator);
		void Terminate();

		void StartRecording(std::vector<Util::Thread>& suspendedThreads, Util::Thread& threadStartingRecording);
		void StopRecording(std::vector<Util::Thread>& suspendedThreads);

		void DisableRecordingOfThread(Util::ThreadId threadId);

		void DoNotRecordThreadExit(Util::ThreadId threadId);
	}
}