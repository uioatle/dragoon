#pragma once

#include <Windows.h>

#define UTIL_ASSERT_MSG(expr, msg) { if (!expr) { Util::HandleFailedAssertion(msg, __FILE__, __LINE__); } }
#define UTIL_ASSERT(expr) UTIL_ASSERT_MSG(expr, "");

#define UTIL_THROW_WIN32(msg) Util::ThrowExceptionWithWin32ErrorCode(msg, __FILE__, __LINE__);

#define UTIL_ROUND_UP_TO_4BYTE_ALIGNMENT(x) (x + 3) & ~0x3;

namespace Util
{
	// TODO These should go in their respective process.h and thread.h
	typedef DWORD ProcessId;
	typedef DWORD ThreadId;

	void HandleFailedAssertion(const char* msg, const char* file, DWORD line);
	void ThrowExceptionWithWin32ErrorCode(const char* msg, const char* file = "", DWORD line = 0);

	DWORD RoundUp(DWORD numToRound, DWORD multiple);
}