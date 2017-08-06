#include "recording_handler.h"

#include "DragoonGlobal\common.h"

#include "lib\Util\include\smart_handle.h"
#include "lib\Util\include\thread.h"
#include "lib\Util\include\trampoline.h"
#include "lib\Util\include\fast_bitset.h"
#include "lib\Util\include\fast_bitset_map.h"

#include <iostream>
#include <vector>
#include <sstream>
#include <memory>
#include <unordered_map>
#include <Windows.h>

namespace Dragoon
{
	namespace RecordingHandler
	{
		// TODO Make sure all of the pointers here are freed at the appropriate times (that is, delete them, don't just disable hooks etc.).

		static Util::Windows::NativeApi::NtQueryVirtualMemory fpNtQueryVirtualMemory;

		static bool isRecording = false;

		static Util::Process* process;
		static Util::Module* dragoonDll;
		static Util::NativeMemoryAllocator* nativeAllocator;

		static Util::Lock memoryLock;

		//static Util::Trampoline* ldrInitializeThunkTrampoline;
		static Util::Trampoline* kiUserExceptionDispatcherTrampoline;

		// There are 65536 possible thread IDs.
		static Util::FastBitsetMap<65536, ThreadRecordingInfo*> threadRecordingInfos;

		static std::vector<Util::ThreadId> onThreadExitThreadIdsToIgnore;

		// ---------------------------------------------------------------------------------------------------------------------------------------

		static NOINLINE void AddThreadRecordingInfo(const Util::ThreadId threadId, ThreadRecordingInfo* const pThreadRecordingInfo)
		{
			// Already exists?
			if (threadRecordingInfos.Test(threadId))
			{
				DragoonGlobal::SafeAbort();
			}

			threadRecordingInfos.Set(threadId, pThreadRecordingInfo);
		}

		static NOINLINE void DeleteThreadRecordingInfo(const Util::ThreadId threadId)
		{
			// First delete the object being pointed to and then remove it from the list. Important to do both.
			delete threadRecordingInfos.Get(threadId);
			threadRecordingInfos.Clear(threadId);
		}

		static NOINLINE ThreadRecordingInfo& GetThreadRecordingInfo(const Util::ThreadId threadId)
		{
			if (!threadRecordingInfos.Test(threadId))
			{
				DragoonGlobal::SafeAbort();
			}

			return *threadRecordingInfos.Get(threadId);
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		// There are 65536 possible thread IDs.
		static Util::FastBitset<65536> threadIdsBeingRecorded;

		static NOINLINE void EnableRecordingOfThread(const Util::ThreadId threadId)
		{
			threadIdsBeingRecorded.Set(threadId);
		}

		NOINLINE void DisableRecordingOfThread(const Util::ThreadId threadId)
		{
			threadIdsBeingRecorded.Clear(threadId);
		}

		static NOINLINE bool IsThreadBeingRecorded(const Util::ThreadId threadId)
		{
			return threadIdsBeingRecorded.Test(threadId);
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		static NOINLINE void DoNotRecordNextSyscall(ThreadRecordingInfo& threadRecordingInfo)
		{
			threadRecordingInfo.doNotRecordNextSyscallSingleshootActive = true;
		}

		static NOINLINE void ResetDoNotRecordNextSyscallSingleshoot(ThreadRecordingInfo& threadRecordingInfo, const Util::ThreadId threadId)
		{
			threadRecordingInfo.doNotRecordNextSyscallSingleshootActive = false;
		}

		static NOINLINE bool ShouldNextSyscallNotBeRecorded(const ThreadRecordingInfo& threadRecordingInfo, const Util::ThreadId threadId)
		{
			return threadRecordingInfo.doNotRecordNextSyscallSingleshootActive;
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		static void HandlePatchedRdtsc(EventLogWriter& eventLogWriter, CONTEXT& ctxOfFaultingInstr)
		{
			// Perform a real rdtsc instruction and store the result in the context struct we'll restore.
			// To pretend the instruction was never emulated in the first place we can optionally subtract from this value (think malware timing checks).
			uint32_t newEax, newEdx;
			__asm
			{
				rdtsc
				mov newEax, eax
				mov newEdx, edx
			}
			ctxOfFaultingInstr.Eax = newEax;
			ctxOfFaultingInstr.Edx = newEdx;

			// Log the rdtsc result to the thread's event log.
			eventLogWriter.LockForWriting();
			eventLogWriter.AddRdtscEvent(ctxOfFaultingInstr.Eax, ctxOfFaultingInstr.Edx);
			eventLogWriter.ReleaseWriteLock();

			// Pretend the exception never happened by restoring the context to the instruction after the faulting instruction.
			// TODO Move function lookup to Init() and put the result in a global variable
			const auto fpNtContinue = (Util::Windows::NativeApi::NtContinue)Util::Windows::NativeApi::GetNtdllFuncPtr("NtContinue");
			ctxOfFaultingInstr.Eip = ctxOfFaultingInstr.Eip + sizeof(unsigned short); // TODO DWORD + 2? That doesn't sound right, but it worked... Check closer, should be uchar + 2

			// Don't record NtContinue.
			DoNotRecordNextSyscall(GetThreadRecordingInfo(GetCurrentThreadId()));

			fpNtContinue(&ctxOfFaultingInstr, FALSE);

			// Should never reach this line.
			// Don't worry about the stack, the ESP in the context struct passed to NtContinue will erase the call stack.
			DragoonGlobal::SafeAbort();
		}

		static void _OnException(void* orgEsp)
		{
			// If the thread isn't being recorded we don't want to log anything, so we return.
			if (!IsThreadBeingRecorded(GetCurrentThreadId()))
			{
				return;
			}

			try
			{
				EventLogWriter& eventLogWriter = *GetThreadRecordingInfo(GetCurrentThreadId()).eventLogWriter;

				// The second DWORD on the stack is a PCONTEXT describing where the exception occurred.
				// The first DWORD is an PEXCEPTION_RECORD, but we're not interested in that.
				CONTEXT* ctxOfFaultingInstr = *(CONTEXT**)((DWORD*)orgEsp + 1);

				// rdtsc instructions patched with 'int 0xAA' get handled here. int 0xAA == 0xCD 0xAA, but it's processed as little endian.
				const bool isFaultingInstrPatchedRdtsc = ctxOfFaultingInstr->Eip != NULL && *(unsigned short*)ctxOfFaultingInstr->Eip == 0xAACD;

				if (isFaultingInstrPatchedRdtsc)
				{
					HandlePatchedRdtsc(eventLogWriter, *ctxOfFaultingInstr);
				}
				else
				{
					// Default exception handling.
					eventLogWriter.LockForWriting();
					eventLogWriter.AddExceptionEvent(*ctxOfFaultingInstr);
					eventLogWriter.ReleaseWriteLock();
				}
			}
			catch (...)
			{
				DragoonGlobal::SafeAbort();
			}
		}

		void __declspec(naked) OnException(void* orgEsp)
		{
			// The trampoline redirects here directly without backing up anything, and we want to
			// return to where we came from as if nothing happened, so we must preserve the state.
			__asm
			{
				pushad
				pushfd

				// No stack frame created/exists so can't use EBP + offset.
				// orgEsp can thus be found at pushad + pushfd + retAddr = 10 * 4 bytes from the top.
				push [esp + 0x0A * 0x04]
				call _OnException

				// 'add esp, 4' may change EFLAGS, using 'pop eax' instead, it doesn't change EFLAGS.
				pop eax

				popfd
				popad

				ret
			}
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		// TODO Should really return all WOW64 DLLs so we can skip all of them.
		static NOINLINE void* GetWow64DllAllocationBase()
		{
			void* dllBase;

			const wchar_t* targetDllName = L"wow64.dll";
			const uint16_t targetDllNameLength = sizeof(targetDllName);

			wchar_t* currentDllName;

			// Perhaps one beautiful day I will replace this with C code. For now this is easier (and less confusing).
			// Structure definitions:
			// - http://blog.rewolf.pl/blog/wp-content/uploads/2013/03/PEB_Evolution.pdf
			// - http://shitwefoundout.com/wiki/Win32_PEB_Loader_data
			// - http://www.codereversing.com/blog/archives/95 (usage)
			// - https://media.paloaltonetworks.com/lp/endpoint-security/blog/how-injected-code-finds-exported-functions.html (another on usage)
			// - http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html
			//
			__asm
			{
				// Retrieve module list.
				mov eax, fs:[0x18] // eax = TEB WOW64
				sub eax, DragoonGlobal::Teb32Offset // eax = TEB64
				mov eax, [eax+0x60] // eax = PEB64
				mov eax, [eax+0x18] // eax = PEB64->PEB_LDR_DATA

				lea edx, [eax+0x10] // edx = Module list head (so we know when to stop traversing list)
				mov eax, [eax+0x10] // eax = PEB_LDR_DATA->InLoadOrderModuleList, or first LDR_MODULE
				jmp compareDllNamesWithoutWraparoundCheck

				// Compare every module name with target name.
				// If there is a match, return the current module's base address.
				// Otherwise, keep traversing. If list wraps around it means module was not found, so we abort.
			compareDllNames:
				cmp eax, edx // list wrapped around
				je moduleNotFound
			compareDllNamesWithoutWraparoundCheck:
				lea ecx, [eax+0x58] // ecx = &ldrModule.BaseDllName (UNICODE_STRING struct)
				add ecx, 8 // skip first two USHORTs + empty uint32_t used for 64-bit alignment to get Buffer field
				mov ecx, [ecx]
				mov currentDllName, ecx

				pushad // don't want to lose module list pointers
			}

			// Can't do this inside __asm block, apparently...
			int comparisonResult = wcscmp(currentDllName, targetDllName);

			__asm
			{
				popad

				mov ecx, comparisonResult
				cmp ecx, 0
				je moduleFound

				mov eax, [eax] // go to next LDR_MODULE in module list
				jmp compareDllNames

			moduleNotFound:
				call DragoonGlobal::SafeAbort

			moduleFound:
				mov ecx, [eax + 0x30] // LDR_MODULE.DllBase
				mov dllBase, ecx
			}

			return dllBase;
		}

		static NOINLINE void* GetAllocationBase(void* addr)
		{
			MEMORY_BASIC_INFORMATION memBasicInfo;

			const auto status = fpNtQueryVirtualMemory(
				process->GetHandle().GetValue(),
				addr,
				Util::Windows::MemoryBasicInformation,
				&memBasicInfo,
				sizeof(memBasicInfo),
				NULL
			);

			if (!Util::Windows::IsNtSuccess(status))
			{
				DragoonGlobal::SafeAbort();
			}

			return memBasicInfo.AllocationBase;
		}

		static NOINLINE void* GetThreads32BitStackAllocationBase(const NT_TIB* pTeb32)
		{
			return GetAllocationBase(pTeb32->StackLimit);
		}

		const void* _x;
		static NOINLINE void* GetThreads64BitStackAllocationBase(const unsigned char* pTeb64)
		{
			// Bind the value to a static variable because otherwise it gets optimized out.
			_x = pTeb64;

			// Calculating offset manually to avoid defining a TEB64 (only got TEB32 at the moment).
			void* teb64StackLimit = (void*)*(uint32_t*)(pTeb64 + 0x10);

			return GetAllocationBase(teb64StackLimit);
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		// There cannot be more than 2k threads on 32-bit Windows, but thread IDs are still in the unsigned 16-bit range.
		Util::FastBitsetMap<65536, ThreadInfo> threadInfos;
		Util::Lock threadInfosLock;

		static NOINLINE void AddToThreadList(const Util::ThreadId threadId, NT_TIB* pTeb32)
		{
			threadInfosLock.Acquire();

			// Already exists?
			if (threadInfos.Test(threadId))
			{
				threadInfosLock.Release();
				return;
			}

			ThreadInfo threadInfo;
			threadInfo.teb32 = pTeb32;
			threadInfo.teb64 = DragoonGlobal::Teb32ToTeb64(threadInfo.teb32);
			threadInfo.stack32BitAllocationBase = GetThreads32BitStackAllocationBase(threadInfo.teb32);
			threadInfo.stack64BitAllocationBase = GetThreads64BitStackAllocationBase((unsigned char*)threadInfo.teb64);

			threadInfos.Set(threadId, threadInfo);
			threadInfosLock.Release();
		}

		static NOINLINE void RemoveFromThreadList(const Util::ThreadId threadId)
		{
			threadInfosLock.Acquire();
			threadInfos.Clear(threadId);
			threadInfosLock.Release();
		}

		static NOINLINE ThreadInfo* GetThreadInfo(const Util::ThreadId threadId)
		{
			if (!threadInfos.Test(threadId))
			{
				return nullptr;
			}

			return &threadInfos.Get(threadId);
		}

		static NOINLINE uint32_t GetThreadInfosSize()
		{
			return threadInfos.GetSize();
		}

		// ---------------------------------------------------------------------------------------------------------------------------------------

		void Init(
			Util::Process* _process,
			Util::Module* _dragoonDll,
			Util::NativeMemoryAllocator* _nativeAllocator
		)
		{
			// Force-cache the function pointer.
			fpNtQueryVirtualMemory = (Util::Windows::NativeApi::NtQueryVirtualMemory)Util::Windows::NativeApi::GetNtdllFuncPtr("NtQueryVirtualMemory");

			process = _process;
			dragoonDll = _dragoonDll;
			nativeAllocator = _nativeAllocator;

			SyscallHandler::RecordingInfo recordingInfo;
			recordingInfo.memoryLock = &memoryLock;
			recordingInfo.wow64DllAllocationBase = GetWow64DllAllocationBase();

			recordingInfo.fpEnableRecordingOfThread = EnableRecordingOfThread;
			recordingInfo.fpDisableRecordingOfThread = DisableRecordingOfThread;
			recordingInfo.fpIsThreadBeingRecorded = IsThreadBeingRecorded;

			recordingInfo.fpGetThreadRecordingInfo = GetThreadRecordingInfo;

			recordingInfo.fpGetThreadInfo = GetThreadInfo;
			recordingInfo.threadInfosSize = GetThreadInfosSize();

			recordingInfo.fpResetDoNotRecordNextSyscallSingleshoot = ResetDoNotRecordNextSyscallSingleshoot;
			recordingInfo.fpShouldNextSyscallNotBeRecorded = ShouldNextSyscallNotBeRecorded;

			SyscallHandler::Init(process, dragoonDll, nativeAllocator, recordingInfo);

			// Installs a trampoline (but doesn't enable it) so that LdrInitializeThunk is intercepted.
			// TODO Note that user mode APC's starting threads at LdrInitializeThunk will most likely run in parallel to the currently active thread on another processor(?).
			// TODO Just keep that in mind with consideration of memory state and such. Shouldn't be a problem since we intercept it immediately.
			/*ldrInitializeThunkTrampoline = new Util::Trampoline(
				process.GetHandle(),
				GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrInitializeThunk"),
				5,
				[&](void* esp) { OnThreadStart(GetCurrentThreadId()); }
			);*/

			kiUserExceptionDispatcherTrampoline = new Util::Trampoline(
				process->GetHandle(),
				GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserExceptionDispatcher"),
				5,
				OnException
			);
		}

		void Terminate()
		{
			// TODO Do everything in Init in reverse.
			// TODO Call StopRecording()? How is this different from dllmain#StopRecording?

			SyscallHandler::Terminate();
		}

		// Warning! Should not assume thread is suspended upon entering.
		// Warning! Perform no library interaction in here.
		void RegisterThread(Util::Thread& thread)
		{
			// TODO If thread already registered, skip this? (might happen if we call StartRecording() and register all threads,
			// then main thread begins at LdrInitializeThunk() and gets redirected into this function again???).

			// When recording, only the threads being recorded will be running (if they enter Dragoon's code it still won't use a new thread but the current one), and we want all those threads in the thread info list.
			AddToThreadList(thread.GetId(), thread.GetTEB32());

			/*
			Pin thread to processor core.
			*/

			// When recording we force all threads onto a single core to get serialized thread scheduling.
			// This way we avoid much work at the cost of speed in parallel programs.
			// IMPORTANT_TODO Do direct syscall, currently doing lib interaction.
			thread.PinToProcessors({ DragoonGlobal::PinnedProcessorId });

			/*
			Create a ThreadRecordingInfo record for the thread.
			*/
			AddThreadRecordingInfo(thread.GetId(), new ThreadRecordingInfo(*GetThreadInfo(thread.GetId()), new EventLogWriter(memoryLock, thread.GetId())));
			
			// Everything from this point onward gets recorded.
			EnableRecordingOfThread(thread.GetId());
		}

		static void UnregisterThread(const Util::ThreadId threadId)
		{
			DisableRecordingOfThread(threadId);
			DeleteThreadRecordingInfo(threadId);
			RemoveFromThreadList(threadId);

			// TODO Reset the thread to run on all processors (or whatever its original affinity was).
		}

		void StartRecording(std::vector<Util::Thread>& suspendedThreads, Util::Thread& threadStartingRecording)
		{
			// Register threads for recording.
			for (auto& suspendedThread : suspendedThreads)
			{
				RegisterThread(suspendedThread);
			}

			// Make sure all future threads also get registered for recording automatically.
			//ldrInitializeThunkTrampoline->Enable();

			// Make sure exceptions get recorded.
			kiUserExceptionDispatcherTrampoline->Enable();

			// Signal to the syscall handler that we're starting to record.
			ThreadInfo threadInfoOfThreadStartingRecording;
			threadInfoOfThreadStartingRecording.teb32 = threadStartingRecording.GetTEB32();
			threadInfoOfThreadStartingRecording.teb64 = DragoonGlobal::Teb32ToTeb64(threadInfoOfThreadStartingRecording.teb32);
			threadInfoOfThreadStartingRecording.stack32BitAllocationBase = GetThreads32BitStackAllocationBase(threadInfoOfThreadStartingRecording.teb32);
			threadInfoOfThreadStartingRecording.stack64BitAllocationBase = GetThreads64BitStackAllocationBase((unsigned char*)threadInfoOfThreadStartingRecording.teb64);

			SyscallHandler::StartRecording(threadInfoOfThreadStartingRecording);

			// We're done.
			isRecording = true;
		}

		NOINLINE void StopRecording(std::vector<Util::Thread>& suspendedThreads)
		{
			if (!isRecording)
			{
				return;
			}

			// Stop recording exceptions.
			//kiUserExceptionDispatcherTrampoline->Disable(); // TODO! trampoline.Disable() not yet implemented, that's why this is commented out

			// Stop registering new threads for recording.
			//ldrInitializeThunkTrampoline->Disable();

			// Unregister threads for recording.
			// TODO What happens if a thread is in the middle of writing to the event log? The event log's write lock will be taken. Can't just cut off the log mid-event?
			for (auto& suspendedThread : suspendedThreads)
			{
				UnregisterThread(suspendedThread.GetId());
			}

			// TODO Move this further up?
			SyscallHandler::StopRecording();

			// We're done.
			isRecording = false;
		}

		// TODO Change this to be similar to how syscall handling registers threads to get a more central structure than this?
		// TODO Do we even need this at all?
		// TODO Shouldn't it be void RecordingHandler::DoNotRecordThreadExit?
		void DoNotRecordThreadExit(const Util::ThreadId threadId)
		{
			onThreadExitThreadIdsToIgnore.emplace_back(threadId);
		}

		//void Recording::OnThreadExit(const Util::ThreadId threadId)
		//{
		//  // TODO If it's the last thread (check threadRecInfos.size()?), also stop the recording?
		//
		//	// Some thread exits we don't want to handle (e.g., the remote thread running StartRecording()).
		//	const auto iterator = std::find(onThreadExitThreadIdsToIgnore.begin(), onThreadExitThreadIdsToIgnore.end(), threadId);
		//	const auto threadIdShouldBeIgnored = iterator != onThreadExitThreadIdsToIgnore.end();
		//
		//	if (threadIdShouldBeIgnored)
		//	{
		//		// Remove the thread ID from the list. The thread has exited, after all...
		//		onThreadExitThreadIdsToIgnore.erase(iterator);
		//		return;
		//	}
		//
		//	// ---------------------------------------------------------------------------------------------------------------------------------------
		//
		//	// TODO
		//	throw std::exception("TODO");
		//
		//	//std::cout << "Thread #" << std::hex << threadId << " exiting" << std::endl;
		//	//UnregisterThread(threadId);
		//
		//	// IMPORTANT_TODO Note freed memory allocations to the log (which presumably belonged to the thread). Before or after unregistering thread?
		//}
	}
}