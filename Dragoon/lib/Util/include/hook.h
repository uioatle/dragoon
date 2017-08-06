#pragma once

#include "smart_handle.h"
#include <array>
#include <vector>

namespace Util
{
	/* WARNING! This class is NOT thread-safe as of this moment! Suspend all threads before use! */
	class Hook
	{
	public:
		enum HookType { HOOK_JMP, HOOK_CALL };

		Hook(const SmartHandle& hProcess, void* hookAddr, DWORD numOriginalBytes, void* destAddr, HookType type);

		void* GetHookAddr() const;
		void* GetDestAddr() const;
		HookType GetType() const;
		std::vector<unsigned char> GetOriginalBytes();

		void Enable();
		void Disable();
	private:
		const SmartHandle& hProcess;

		void* hookAddr;
		void* destAddr;
		const HookType type;
		const DWORD numOriginalBytes;

		std::array<unsigned char, 5> hookBytes;
		std::vector<unsigned char> originalBytes;

		void BackupOriginalBytes();
	};
}