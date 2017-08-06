#include "hook.h"
#include "memory_region.h"

namespace Util
{
	Hook::Hook(const SmartHandle& hProcess, void* hookAddr, const DWORD numOriginalBytes, void* destAddr, const HookType type) :
		hProcess(hProcess), hookAddr(hookAddr), numOriginalBytes(numOriginalBytes), destAddr(destAddr), type(type)
	{
		if (numOriginalBytes < 1)
		{
			throw std::invalid_argument("numOriginalBytes must be >= 1");
		}

		hookBytes.data()[0] = (type == HOOK_JMP) ? 0xE9 : 0xE8;
		const DWORD offset = (DWORD)destAddr - ((DWORD)hookAddr + hookBytes.size());
		*(DWORD*)&hookBytes.data()[1] = offset;
	}

	void* Hook::GetHookAddr() const
	{
		return hookAddr;
	}

	void* Hook::GetDestAddr() const
	{
		return destAddr;
	}

	Util::Hook::HookType Hook::GetType() const
	{
		return type;
	}

	void Hook::BackupOriginalBytes()
	{
		unsigned char _originalBytes[16];

		MemoryRegion hookAddrMemRegion(hProcess, hookAddr, numOriginalBytes);
		hookAddrMemRegion.ReadData(&_originalBytes, numOriginalBytes);

		for (DWORD i = 0; i < numOriginalBytes; i++)
		{
			originalBytes.emplace_back(_originalBytes[i]);
		}
	}

	std::vector<unsigned char> Hook::GetOriginalBytes()
	{
		if (originalBytes.empty())
		{
			BackupOriginalBytes();
		}
		
		return originalBytes;
	}

	void Hook::Enable()
	{
		if (originalBytes.empty())
		{
			BackupOriginalBytes();
		}

		MemoryRegion hookAddrMemRegion(hProcess, hookAddr, hookBytes.size());
		hookAddrMemRegion.WriteData(hookBytes.data(), hookBytes.size());
	}

	void Hook::Disable()
	{
		// Hook was never enabled?
		if (originalBytes.empty())
		{
			return;
		}

		MemoryRegion hookAddrMemRegion(hProcess, hookAddr, originalBytes.size());
		hookAddrMemRegion.WriteData(originalBytes.data(), originalBytes.size());
	}
}