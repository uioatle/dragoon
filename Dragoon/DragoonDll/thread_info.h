#pragma once

#include <Windows.h>

namespace Dragoon
{
	struct ThreadInfo
	{
		NT_TIB* teb32;
		void* teb64;
		void* stack32BitAllocationBase;
		void* stack64BitAllocationBase;

		inline void* GetTEBAllocationBase() const
		{
			return teb64;
		}
	};
}