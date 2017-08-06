#pragma once

#include "smart_handle.h"
#include "common.h"
#include "thread.h"
#include "memory_region.h"
#include <vector>

namespace Util
{
	class Process
	{
	public:
		Process(const SmartHandle& hProcess, ProcessId id) : handle(hProcess), id(id) {}

		ProcessId GetId() const;
		const SmartHandle& GetHandle() const;

		std::vector<ThreadId> GetThreadIds() const;
		std::vector<Thread> GetThreads() const;
		std::vector<MEMORY_BASIC_INFORMATION> GetMemoryRegionHeaders() const;
		std::vector<MemoryRegion> GetMemoryRegions() const;
	private:
		const SmartHandle& handle;
		ProcessId id;
	};
}