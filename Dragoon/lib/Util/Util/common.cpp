#include "common.h"
#include <sstream>
#include <exception>

namespace Util
{
	void HandleFailedAssertion(const char* msg, const char* file, DWORD line)
	{
		std::stringstream ss;
		ss << "ASSERTION ERROR - Message: " << msg << ", File: " << file << ", Line: " << line;
		throw std::exception(ss.str().c_str());
	}

	void ThrowExceptionWithWin32ErrorCode(const char* msg, const char* file, const DWORD line)
	{
		std::stringstream ss;
		ss << msg << " - Win32 Error code: " << GetLastError();

		if (file != "" && line != 0)
		{
			ss << ", File: " << file << ", Line: " << line;
		}

		throw std::exception(ss.str().c_str());
	}

	// Credit Mark Ransom: http://stackoverflow.com/questions/3407012/c-rounding-up-to-the-nearest-multiple-of-a-number
	DWORD RoundUp(const DWORD numToRound, const DWORD multiple)
	{
		if (multiple == 0)
		{
			return numToRound;
		}

		const DWORD remainder = numToRound % multiple;
		if (remainder == 0)
		{
			return numToRound;
		}

		return numToRound + multiple - remainder;
	}
}