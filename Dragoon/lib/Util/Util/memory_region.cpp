#include "memory_region.h"
#include "common.h"
#include <sstream>

namespace Util
{
	// TODO If you pass in NULL as base address you can't use some functions(?). Validate per function.
	MemoryRegion::MemoryRegion(const SmartHandle& hProcess, void* baseAddr, const DWORD size) :
		hProcess(hProcess), baseAddr(baseAddr), size(size)
	{
		isLocal = GetProcessId(hProcess.GetValue()) == GetCurrentProcessId();
	}

	void* MemoryRegion::GetBaseAddr() const
	{
		return baseAddr;
	}

	DWORD MemoryRegion::GetSizeAtConstruction() const
	{
		return size;
	}

	MEMORY_BASIC_INFORMATION MemoryRegion::GetHeader() const
	{
		MEMORY_BASIC_INFORMATION memBasicInfo;

		if (!VirtualQueryEx(hProcess.GetValue(), baseAddr, &memBasicInfo, sizeof(memBasicInfo)))
		{
			UTIL_THROW_WIN32("VirtualQueryEx failed");
		}

		return memBasicInfo;
	}

	DWORD MemoryRegion::GetProtection() const
	{
		return GetHeader().Protect;
	}

	bool MemoryRegion::IsFree() const
	{
		return GetHeader().Type == 0x00000000; // TODO Also add a check for MEM_FREE state?
	}

	bool MemoryRegion::IsGuarded() const
	{
		return HasProtectionFlag(PAGE_GUARD);
	}

	void MemoryRegion::DisableGuard()
	{
		ClearProtectionFlag(PAGE_GUARD);
	}

	void MemoryRegion::ReadData(void* buffer, const DWORD numBytesToRead)
	{
		if (isLocal)
		{
			CopyMemory(buffer, baseAddr, numBytesToRead);
		}
		else
		{
			if (!ReadProcessMemory(hProcess.GetValue(), baseAddr, buffer, numBytesToRead, NULL))
			{
				UTIL_THROW_WIN32("ReadProcessMemory failed");
			}
		}
	}

	bool MemoryRegion::IsWritable() const
	{
		return HasProtectionFlag(PAGE_EXECUTE_READWRITE) ||
			HasProtectionFlag(PAGE_EXECUTE_WRITECOPY) ||
			HasProtectionFlag(PAGE_READWRITE) ||
			HasProtectionFlag(PAGE_WRITECOPY) ||
			HasProtectionFlag(PAGE_WRITECOMBINE);
	}

	bool MemoryRegion::MakeWritable()
	{
		if (IsWritable())
		{
			return false;
		}

		const DWORD oldProtection = GetProtection();
		DWORD newProtection;

		switch (oldProtection)
		{
		case PAGE_EXECUTE:
		case PAGE_EXECUTE_READ:
		case PAGE_EXECUTE_READWRITE:
		case PAGE_EXECUTE_WRITECOPY:
			newProtection = PAGE_EXECUTE_READWRITE;
			break;
		case PAGE_READONLY:
		case PAGE_READWRITE:
		case PAGE_WRITECOPY:
			newProtection = PAGE_READWRITE;
			break;
		default:
			newProtection = PAGE_READWRITE;
			break;
		}

		// We're discarding any page guards that may exist.
		// Can't write with those active anyway, and they'll be reverted if we revert the protection, so it should be fine.
		ChangeProtection(newProtection);

		return true;
	}

	void MemoryRegion::WriteData(const void* data, const DWORD dataSize, const bool makeTemporarilyWritable)
	{
		if (dataSize > size) throw std::invalid_argument("Data can't fit in region");
		
		bool wasMadeWritable = false;
		if (makeTemporarilyWritable)
		{
			wasMadeWritable = MakeWritable();
		}
		const auto shouldRevertProtection = [&](){ return wasMadeWritable; };

		try
		{
			if (isLocal)
			{
				CopyMemory(baseAddr, data, dataSize);
			}
			else
			{
				if (!WriteProcessMemory(hProcess.GetValue(), baseAddr, data, dataSize, NULL))
				{
					UTIL_THROW_WIN32("WriteProcessMemory failed");
				}
			}

			if (!FlushInstructionCache(hProcess.GetValue(), NULL, NULL))
			{
				UTIL_THROW_WIN32("FlushInstructionCache failed");
			}
		}
		catch (const std::exception& e)
		{
			// Stand-in for lack of finally-clause.
			if (shouldRevertProtection())
			{
				RevertToPreviousProtection();
			}

			throw;
		}

		if (shouldRevertProtection())
		{
			RevertToPreviousProtection();
		}
	}

	void MemoryRegion::MakeExecutable()
	{
		// TODO Use SetProtectionFlag() with a switch depending on which protection is currently active (e.g. for READWRITE you do EXECUTE_READWRITE)
		ChangeProtection(PAGE_EXECUTE_READWRITE);
	}

	DWORD MemoryRegion::ChangeProtection(const DWORD newProtection)
	{
		if (newProtection % 2 != 0) throw std::invalid_argument("New protection must be divisible by 2");

		if (!VirtualProtectEx(hProcess.GetValue(), baseAddr, size, newProtection, (DWORD*)&previousProtection))
		{
			UTIL_THROW_WIN32("VirtualProtectEx failed");
		}

		return previousProtection;
	}

	DWORD MemoryRegion::RevertToPreviousProtection()
	{
		return ChangeProtection(previousProtection);
	}

	bool MemoryRegion::HasProtectionFlag(const DWORD protectionFlag) const
	{
		return GetProtection() & protectionFlag;
	}

	void MemoryRegion::SetProtectionFlag(const DWORD protectionFlag)
	{
		ChangeProtection(GetProtection() | protectionFlag);
	}

	void MemoryRegion::ClearProtectionFlag(const DWORD protectionFlag)
	{
		ChangeProtection(GetProtection() & ~protectionFlag);
	}

	void* MemoryRegion::Allocate(const DWORD allocationType, const DWORD protection)
	{
		// TODO Validate allocationType and protection
		void* allocatedAddr = VirtualAllocEx(hProcess.GetValue(), baseAddr, size, allocationType, protection);

		if (!allocatedAddr)
		{
			std::stringstream errorMsg;
			errorMsg << "Failed to allocate memory region " << std::hex << baseAddr;
			Util::ThrowExceptionWithWin32ErrorCode(errorMsg.str().c_str(), __FILE__, __LINE__);
		}

		baseAddr = allocatedAddr;
		return allocatedAddr;
	}

	void MemoryRegion::Free(const SmartHandle& hProcess, void* allocationBase)
	{
		if (!VirtualFreeEx(hProcess.GetValue(), allocationBase, 0, MEM_RELEASE))
		{
			UTIL_THROW_WIN32("VirtualFreeEx failed");
		}
	}
}