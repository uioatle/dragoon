#pragma once

#include "event_log_writer.h"
#include "thread_info.h"

#include "lib\Util\include\system.h"
#include "lib\Util\include\fast_bitset.h"

#include <vector>
#include <bitset>
#include <Windows.h>

namespace Dragoon
{
	struct ThreadRecordingInfo
	{
		ThreadRecordingInfo(const ThreadInfo& threadInfo, EventLogWriter* eventLogWriter) : threadInfo(threadInfo), eventLogWriter(eventLogWriter)
		{
		}

		~ThreadRecordingInfo()
		{
			delete eventLogWriter;
		}

		const ThreadInfo& threadInfo;

		// We hold ownership of this pointer.
		EventLogWriter* eventLogWriter;

		unsigned char stackContentsContainer[UTIL_SYSTEM_PAGE_SIZE * 256];
		bool doNotRecordNextSyscallSingleshootActive = false;
	};
}