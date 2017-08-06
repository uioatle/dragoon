#pragma once

#include "smart_handle.h"
#include "system.h"

#include <functional>
#include <memory>
#include <Windows.h>

namespace Util
{
	/*
	WARNING! This class is NOT thread-safe as of this moment! Suspend all threads before use!

	The trampoline class redirects execution from a specified location to a custom function (destFunc).
	destFunc will be called with the current stack pointer (ESP) as the first argument in case
	access to the original context before entering the trampoline is required for setup or backup.

	After calling destFunc the original bytes overwritten by the redirection mechanism are executed
	before execution resumes where the initial redirection took place.
	*/
	class Trampoline
	{
	public:
		Trampoline(const SmartHandle& hProcess, void* hookAddr, DWORD numOriginalBytes, void(*destFunc)(void* orgEsp));
		~Trampoline();

		void Enable();
		void Disable();
	private:
		const SmartHandle& hProcess;
		void* hookAddr;
		DWORD numOriginalBytes;

		unsigned char* trampolineArea;
		const DWORD trampolineAreaSize = 60;

		// Must always be small enough to fit redirection instructions in trampoline area.
		const uint32_t maxAllowedNumOriginalBytes = 40;

		void(*destFunc)(void* orgEsp);
	};
}