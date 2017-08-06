#pragma once

#include <Windows.h>

namespace Util
{
	namespace Windows
	{
		typedef DWORD KPRIORITY;

		typedef struct _UNICODE_STRING {
			USHORT Length;
			USHORT MaximumLength;
			PWSTR  Buffer;
		} UNICODE_STRING, *PUNICODE_STRING;

		typedef struct
		{
			PVOID UniqueProcess;
			PVOID UniqueThread;
		} CLIENT_ID;

		typedef struct
		{
			NTSTATUS ExitStatus;
			PVOID TebBaseAddress;
			CLIENT_ID ClientId;
			KAFFINITY AffinityMask;
			KPRIORITY Priority;
			KPRIORITY BasePriority;
		} THREAD_BASIC_INFORMATION;

		enum THREAD_INFORMATION_CLASS
		{
			ThreadBasicInformation,
			ThreadTimes,
			ThreadPriority,
			ThreadBasePriority,
			ThreadAffinityMask,
			ThreadImpersonationToken,
			ThreadDescriptorTableEntry,
			ThreadEnableAlignmentFaultFixup,
			ThreadEventPair,
			ThreadQuerySetWin32StartAddress,
			ThreadZeroTlsCell,
			ThreadPerformanceCount,
			ThreadAmILastThread,
			ThreadIdealProcessor,
			ThreadPriorityBoost,
			ThreadSetTlsArrayAddress,
			ThreadIsIoPending,
			ThreadHideFromDebugger
		};

		// TODO This needs to be split into 32- and 64-bit structs!
		typedef struct _NT_TIB
		{
			PEXCEPTION_REGISTRATION_RECORD ExceptionList;
			PVOID StackBase;
			PVOID StackLimit;
			PVOID SubSystemTib;
			union
			{
				PVOID FiberData;
				ULONG Version;
			};
			PVOID ArbitraryUserPointer;
			PNT_TIB Self;
		} NT_TIB, *PNT_TIB;

		typedef enum _SECTION_INHERIT
		{
			ViewShare = 1,
			ViewUnmap = 2
		} SECTION_INHERIT;

		typedef PVOID PIO_APC_ROUTINE; // Placeholder, not real typedef

		typedef struct _IO_STATUS_BLOCK {
			union {
				NTSTATUS Status;
				PVOID    Pointer;
			};
			ULONG_PTR Information;
		} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

		typedef enum _MEMORY_INFORMATION_CLASS
		{
			MemoryBasicInformation
		} MEMORY_INFORMATION_CLASS;

		bool IsNtSuccess(NTSTATUS status);

		namespace NativeApi
		{
			// Warning! Make sure to call Init() before using anything from this namespace!

			/*
			 * WARNING! Everything that resides within this namespace must be handled with the native API only!
			 * What this means is that std::string, std::map, exceptions and all such are banned, because internally they
			 * may make use of Windows functionality that affects the state of internal modules such as ntdll, kernel32 etc.
			 * We should not make any assumptions about how these types and functions are going to be used, so they need to be
			 * as detached from the operating system as possible.
			 * The namespace should be kept small so that the work required to maintain it is as small as possible.
			 */

			typedef NTSTATUS(WINAPI *NtQueryInformationThread)(HANDLE ThreadHandle, THREAD_INFORMATION_CLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
			typedef NTSTATUS(WINAPI *NtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
			typedef NTSTATUS(WINAPI *NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
			typedef NTSTATUS(WINAPI *NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
			typedef NTSTATUS(WINAPI *NtFreeVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
			typedef NTSYSAPI NTSTATUS(NTAPI *NtDelayExecution)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
			typedef NTSTATUS(WINAPI *NtWriteFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
			typedef NTSYSAPI NTSTATUS(NTAPI *NtResetWriteWatch)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG RegionSize);
			typedef NTSYSAPI NTSTATUS(NTAPI *NtGetWriteWatch)(HANDLE ProcessHandle, ULONG Flags, PVOID BaseAddress, ULONG RegionSize, PVOID* Addresses, ULONG_PTR* AddressesCount, PULONG Granularity);
			typedef NTSTATUS(WINAPI *NtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
			typedef NTSTATUS(NTAPI *NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
			typedef NTSTATUS(NTAPI *NtResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);
			typedef NTSTATUS(NTAPI *NtContinue)(PCONTEXT ThreadContext, BOOLEAN RaiseAlert);
			typedef NTSTATUS(NTAPI *NtClose)(HANDLE Handle);

			void Init();
			void* GetNtdllFuncPtr(const char* funcName);

			void YieldTimeSlice();
		}
	}
}