#pragma once

#include "paths.h"
#include "logging.h"

#include <cstdint>

#include <Windows.h>

namespace DragoonGlobal
{
/* Credit: Steve Karg */
/* a=target variable, b=bit number to act upon 0-n */
#define BIT_SET(a,b) ((a) |= (1<<(b)))
#define BIT_CLEAR(a,b) ((a) &= ~(1<<(b)))
#define BIT_FLIP(a,b) ((a) ^= (1<<(b)))
#define BIT_CHECK(a,b) ((a) & (1<<(b)))
/* x=target variable, y=mask */
#define BITMASK_SET(x,y) ((x) |= (y))
#define BITMASK_CLEAR(x,y) ((x) &= (~(y)))
#define BITMASK_FLIP(x,y) ((x) ^= (y))
#define BITMASK_CHECK(x,y) (((x) & (y)) == (y))
/* ----- */

#define C_DLLEXPORT extern "C" __declspec(dllexport)
#define NOINLINE __declspec(noinline)

#define DRAGOON_GLOBAL_EVENT_LOG_WRITER_BUFFER_SIZE 1024 * 32

	typedef void* BaseAddr;

	const DWORD MaxNumThreads = 1024;
	const unsigned char PinnedProcessorId = 0;
	const uint32_t MaxSyscalls = 100000000;

	const uint32_t Teb32Offset = 0x2000;
	inline void* Teb32ToTeb64(void* pTeb32)
	{
		return (unsigned char*)pTeb32 - Teb32Offset;
	}

	void SafeAbort();

	bool IsAlignedTo4Bytes(uint32_t addr);
	uint32_t AlignTo4Bytes(uint32_t addr);
}