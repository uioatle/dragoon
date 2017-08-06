#pragma once

#include "smart_handle.h"
#include <Windows.h>

namespace Util
{
	class MemoryRegion
	{
		const SmartHandle& hProcess;
		void* baseAddr;
		const DWORD size;
		bool isLocal;

		DWORD previousProtection;
	public:
		MemoryRegion(const SmartHandle& hProcess, void* baseAddr, DWORD size);

		void* GetBaseAddr() const;
		DWORD GetSizeAtConstruction() const;
		MEMORY_BASIC_INFORMATION GetHeader() const;
		DWORD GetProtection() const;

		bool IsFree() const;

		bool IsGuarded() const;
		void DisableGuard();

		void ReadData(void* buffer, DWORD numBytesToRead);

		bool IsWritable() const;
		bool MakeWritable();
		void WriteData(const void* data, DWORD dataSize, bool makeTemporarilyWritable = true);

		void MakeExecutable();

		DWORD ChangeProtection(DWORD newProtection);
		DWORD RevertToPreviousProtection();

		bool HasProtectionFlag(DWORD protectionFlag) const;
		void SetProtectionFlag(DWORD protectionFlag);
		void ClearProtectionFlag(DWORD protectionFlag);

		void* Allocate(DWORD allocationType, DWORD protection);
		static void Free(const SmartHandle& hProcess, void* allocationBase);
	};
}