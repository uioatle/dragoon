#include "windefs.h"

#include <unordered_map>

namespace Util
{
	namespace Windows
	{
		bool IsNtSuccess(const NTSTATUS status)
		{
			return status >= 0;
		}

		namespace NativeApi
		{
			// Warning! Make sure to call Init() before using anything from this namespace!

			// Easier to debug with this than exceptions.
			__declspec(noinline, naked) void SafeError()
			{
				__asm int 3;
				__asm int 1;
			}

			// Using "dangerous", non-plain implementation to avoid implementing it ourselves for now.
			std::unordered_map<const char*, void*> cachedFuncAddrs;

			// Warning! This is a hack. Pre-allocate the map space so we (hopefully) won't access the heap unexpectedly.
			// TODO Don't forget this. If it works it's just because Init() is called and all functions are explicitly cached early.
			// TODO The map WILL be heap allocated! It may be that it wasn't because the NativeMemoryAllocator was initialized before everything else, but doubt it.
			bool hasBeenInitialized = false;
			__declspec(noinline) void Init()
			{
				if (hasBeenInitialized)
				{
					return;
				}

				cachedFuncAddrs.reserve(32);
				hasBeenInitialized = true;
			}

			__declspec(noinline) void* GetNtdllFuncPtr(const char* funcName)
			{
				if (!hasBeenInitialized)
				{
					SafeError();
				}

				const auto it = cachedFuncAddrs.find(funcName);
				if (it != cachedFuncAddrs.end())
				{
					return it->second;
				}

				void* fp = GetProcAddress(GetModuleHandleA("ntdll.dll"), funcName);
				if (!fp)
				{
					SafeError();
				}

				// Cache the result so we never have to use GetModuleHandle (AKA the WinAPI) again.
				cachedFuncAddrs[funcName] = fp;
				return fp;
			}

			void YieldTimeSlice()
			{
				const auto fpNtDelayExecution = (NtDelayExecution)GetNtdllFuncPtr("NtDelayExecution");

				// Same as Sleep(0) which yields immediately.
				LARGE_INTEGER delayInterval;
				delayInterval.QuadPart = 0;

				if (!IsNtSuccess(fpNtDelayExecution(0, &delayInterval)))
				{
					SafeError();
				}
			}
		}
	}
}