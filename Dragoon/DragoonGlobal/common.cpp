#include "common.h"

namespace DragoonGlobal
{
	__declspec(noinline, naked) void SafeAbort()
	{
		// This doesn't do anything, it's just an arbitrary pattern that tells us we crashed "gracefully" (= without using libraries).
		__asm int 3;
		__asm int 1;
	}

	NOINLINE bool IsAlignedTo4Bytes(const uint32_t addr)
	{
		return addr & 0x3;
	}

	NOINLINE uint32_t AlignTo4Bytes(const uint32_t addr)
	{
		return addr & ~0x3;
	}
}