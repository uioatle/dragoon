#pragma once

#include <Windows.h>

#define UTIL_SYSTEM_PAGE_SIZE 0x1000

namespace Util
{
	class System
	{
	public:
		static void* KUSER_SHARED_DATA;
		static void* PEB32_Base;
		static void* PEB64_Base;

		static const DWORD TEB32_Offset;

		static const DWORD PageSize;
		static const DWORD AllocationGranularitySize;
	};
}