#include <cstdint>
#include <cstdio>
#include <exception>
#include <chrono>
#include <iostream>
#include <Windows.h>

// Nanoseconds high resolution clock, because std::chrono's is typedeffed to system_clock (<bad word> you, VC++ devs!!!!!!!!!!!!!!!!!!!!!).
// Credit: https://stackoverflow.com/users/369872/david
// https://stackoverflow.com/questions/16299029/resolution-of-stdchronohigh-resolution-clock-doesnt-correspond-to-measureme
struct HighResClock
{
	typedef long long                               rep;
	typedef std::nano                               period;
	typedef std::chrono::duration<rep, period>      duration;
	typedef std::chrono::time_point<HighResClock>   time_point;
	static const bool is_steady = true;

	static time_point now();
};
namespace
{
	const long long g_Frequency = []() -> long long
	{
		LARGE_INTEGER frequency;
		QueryPerformanceFrequency(&frequency);
		return frequency.QuadPart;
	}();
}
HighResClock::time_point HighResClock::now()
{
	LARGE_INTEGER count;
	QueryPerformanceCounter(&count);
	return time_point(duration(count.QuadPart * static_cast<rep>(period::den) / g_Frequency));
}
// ------------------

// Using a global variable because otherwise it'll be put on the stack and the stack usually gets dumped.
uint32_t myNumber = 0;
void WIPTestMemoryModificationDetection()
{
	/* TODO Test detecting allocated regions */
	/* TODO Test detecting freed regions */

	/* TODO Test detecting modified regions */
	const uint32_t newNumber = 0xAABBCCDD;
	WriteProcessMemory(GetCurrentProcess(), &myNumber, &newNumber, sizeof(newNumber), NULL);
}

void WIPTestExceptions()
{
	// Both hardware exceptions...
	__try
	{
		int* ptr = NULL;
		*ptr = 0xAABBCCDD;
	}
	__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		// TODO
		__asm int 3;
	}

	// And software exceptions... (NtRaiseException).
	RaiseException(1, 0, 0, NULL);
}

void TestRdtsc()
{
	DWORD expectedEdx;
	DWORD oldEflags;
	__asm
	{
		push eax
		push edx

		// Save rdtsc result.
		rdtsc
		mov expectedEdx, edx

		// Save EFLAGS.
		pushfd
		mov eax, [esp]
		mov oldEflags, eax
		popfd

		pop edx
		pop eax
	}

	// Perform emulated rdtsc.
	__asm int 0xAA

	DWORD resultingEdx;
	DWORD newEflags;
	__asm
	{
		push eax
		push edx

		// Extract the rdtsc result.
		mov resultingEdx, edx

		// Save EFLAGS.
		pushfd
		mov eax, [esp]
		mov newEflags, eax
		popfd

		pop edx
		pop eax
	}

	// Compare results with expected results.
	// EDXs should match up, but since it's time we're talking about here the newest EDX may just have rolled over onto the next number, and that's fine.
	if (resultingEdx != expectedEdx && resultingEdx != expectedEdx + 1)
	{
		throw std::exception("rdtsc emulation failed on EDX (high-order dword) comparison");
	}

	if (newEflags != oldEflags)
	{
		throw std::exception("rdtsc emulation failed to correctly restore EFLAGS");
	}
}

int main(int argc, char** argv)
{
	__asm int 3;
	VirtualAlloc((void*)0x50000000, 0x12345, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	VirtualFree((void*)0x50000000, 0, MEM_RELEASE);
	__asm int 3;

	//WIPTestMemoryModificationDetection();
	//WIPTestExceptions();
	//TestRdtsc();

	enum MEMORY_INFORMATION_CLASS { MemoryBasicInformation };
	typedef NTSTATUS(NTAPI *NtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

	const auto fpNtQueryVirtualMemory = (NtQueryVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory");
	MEMORY_BASIC_INFORMATION memBasicInfo;

	__asm int 3;

	uint32_t val = 0;

	auto startTime = HighResClock::now();

	uint32_t k = 0;

	for (uint32_t i = 0; i < 1000; i++)
	{
		if (k % 10000 == 0)
		{
			k = 0;
		}

		for (uint32_t w = 0; w < 1000000; ++w)
		{
			if (w % 10000000 == 0)
			{
				val = rand();
			}
		}

		fpNtQueryVirtualMemory(GetCurrentProcess(), (void*)(0x10000 * k), MemoryBasicInformation, &memBasicInfo, sizeof(memBasicInfo), NULL);

		++k;
	}

	auto endTime = HighResClock::now();

	__asm int 3;

	auto difference = endTime - startTime;
	std::cout << "Elapsed time: " << std::chrono::duration_cast<std::chrono::nanoseconds>(difference).count() << " ns" << std::endl;

	__asm int 3;

	// To avoid having the inner loop optimized out.
	std::cout << val << std::endl;

	return 0;
}