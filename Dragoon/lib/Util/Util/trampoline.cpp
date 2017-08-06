#include "trampoline.h"
#include "common.h"
#include "hook.h"
#include "memory_region.h"

namespace Util
{
	Trampoline::Trampoline(const SmartHandle& hProcess, void* hookAddr, const DWORD numOriginalBytes, void(*destFunc)(void* esp)) :
		hProcess(hProcess), hookAddr(hookAddr), numOriginalBytes(numOriginalBytes), destFunc(destFunc)
	{
		if (destFunc == nullptr)
		{
			throw std::invalid_argument("destFunc was nullptr");
		}

		if (numOriginalBytes > maxAllowedNumOriginalBytes)
		{
			throw std::invalid_argument("numOriginalBytes is too large and won't fit in trampoline area buffer");
		}
	}

	Trampoline::~Trampoline()
	{
		if (trampolineArea != nullptr)
		{
			MemoryRegion::Free(hProcess, trampolineArea);
		}
	}

	void Trampoline::Enable()
	{
		/*
		The trampoline area will end up looking like this after this method has completed:

		trampolineArea:
			push eax ; original code is redirected to this line
			lea eax, [esp+4] ; (ESP before pushing EAX)
			push eax ; first function argument
			call Trampoline::DestFuncStub ; call the function being trampolined to
			pop eax ; remove arg from stack. avoiding ADD ESP, 4 in case of EFLAGS change
			pop eax ; ensures original EAX is preserved
			<nops>
			<original bytes> ; execute the original bytes overwritten by the hook
			jmp hookedAddr + sizeof(hook) ; continue after the hook at the original location
		*/

		/* Trampoline already enabled? */
		if (trampolineArea != nullptr)
		{
			return;
		}

		/*
		The trampoline area must be executable, which requires it to span a full page despite the area itself using only a few bytes,
		because if we change the page protection it might interfere with other unrelated code, so we want to isolate the executable area
		to be as small as possible. The smallest possible granularity where we can change protection freely is a single page.
		*/
		unsigned char* const trampolineArea = (unsigned char*)VirtualAlloc(NULL, System::PageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!trampolineArea) UTIL_THROW_WIN32("VirtualAlloc failed");

		/* Fill trampoline area with nops */
		for (DWORD i = 0; i < trampolineAreaSize; i++)
		{
			trampolineArea[i] = 0x90;
		}

		/* Create the hook that takes us to the trampoline area. Don't enable it yet */
		Hook trampolineHook(
			hProcess,
			hookAddr,
			numOriginalBytes,
			trampolineArea,
			Hook::HookType::HOOK_JMP
		);

		/* Assemble some code at the beginning of the trampoline area */
		std::vector<unsigned char> instrBytes;

		// PUSH EAX (see POP EAX below for explanation).
		instrBytes.emplace_back(0x50);

		// LEA EAX, [ESP+4] (ESP before pushing EAX).
		instrBytes.emplace_back(0x8D);
		instrBytes.emplace_back(0x44);
		instrBytes.emplace_back(0x24);
		instrBytes.emplace_back(0x04);

		// PUSH EAX. This will be the argument to the upcoming CALL.
		instrBytes.emplace_back(0x50);

		// Copy the assembled instructions to the beginning of the trampoline area.
		CopyMemory(trampolineArea, instrBytes.data(), instrBytes.size());

		/* CALL destFunc */
		// To avoid having to calculate the CALL offset manually we install a hook which uses a CALL instead of a JMP.
		// When we enable it, the CALL instruction will be written to the trampoline area after the instructions we just wrote.
		Hook(hProcess, trampolineArea + instrBytes.size(), 5, destFunc, Util::Hook::HookType::HOOK_CALL).Enable();

		// Remove argument from stack with POP EAX twice (ADD ESP, 4 may change EFLAGS, POP EAX won't).
		// Need the instruction twice to preserve the original EAX (hence the PUSH EAX earlier).
		const uint32_t oldInstrBytesSize = instrBytes.size();
		instrBytes.clear();

		instrBytes.emplace_back(0x58);
		instrBytes.emplace_back(0x58);

		CopyMemory(trampolineArea + oldInstrBytesSize + 5, instrBytes.data(), instrBytes.size());

		/*
		Create a jump back to the where the original instruction was hooked at the very end of the trampoline area,
		which jumps past the hook so we don't end up in the trampoline again.
		*/
		Hook trampolineExitHook(
			hProcess,
			trampolineArea + trampolineAreaSize - trampolineHook.GetOriginalBytes().size(),
			5,
			(unsigned char*)trampolineHook.GetHookAddr() + trampolineHook.GetOriginalBytes().size(),
			Hook::HookType::HOOK_JMP
		);
		trampolineExitHook.Enable();

		/* Write original bytes overwritten by the hook to the trampoline area before the exit hook */
		CopyMemory(
			(unsigned char*)trampolineExitHook.GetHookAddr() - trampolineHook.GetOriginalBytes().size(),
			trampolineHook.GetOriginalBytes().data(),
			trampolineHook.GetOriginalBytes().size()
		);

		/* Make the trampoline area executable (but not writable for security reasons) */
		MemoryRegion(
			hProcess,
			trampolineArea,
			trampolineAreaSize
		).ChangeProtection(PAGE_EXECUTE_READ);

		/* Start redirecting to the trampoline area */
		trampolineHook.Enable();
	}

	void Trampoline::Disable()
	{
		throw std::exception("NOT IMPLEMENTED"); // TODO
	}
}