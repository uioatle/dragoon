#pragma once

#include "thread_recording_info.h"

#include "lib\Util\include\common.h"
#include "lib\Util\include\process.h"
#include "lib\Util\include\native_memory_allocator.h"
#include "lib\Util\include\module.h"

#include <unordered_map>

namespace Dragoon
{
	namespace SyscallHandler
	{
		struct RecordingInfo
		{
			Util::Lock* memoryLock;
			void* wow64DllAllocationBase;

			ThreadRecordingInfo& (*fpGetThreadRecordingInfo)(Util::ThreadId threadId);

			ThreadInfo* (*fpGetThreadInfo)(Util::ThreadId threadId);
			uint32_t threadInfosSize;

			void (*fpEnableRecordingOfThread)(Util::ThreadId threadId);
			void (*fpDisableRecordingOfThread)(Util::ThreadId threadId);
			bool (*fpIsThreadBeingRecorded)(Util::ThreadId threadId);

			void (*fpResetDoNotRecordNextSyscallSingleshoot)(ThreadRecordingInfo& threadRecordingInfo, const Util::ThreadId threadId);
			bool (*fpShouldNextSyscallNotBeRecorded)(const ThreadRecordingInfo& threadRecordingInfo, const Util::ThreadId threadId);
		};

		void Init(Util::Process* process, Util::Module* dragoonDll, Util::NativeMemoryAllocator* nativeAllocator, const RecordingInfo& recordingInfo);
		void Terminate();
		
		void StartRecording(const ThreadInfo& threadInfoOfThreadStartingRecording);
		void StopRecording();
		
		void ResetSyscallCounterSinceRecordingStart();
	}
}