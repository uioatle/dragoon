#include "thread.h"
#include <sstream>

namespace Util
{
	Thread::Thread(const ThreadId id, const ProcessId processId) : id(id), processId(processId), _pHandle(nullptr)
	{
	}

	void Thread::PerformMove(Thread& other)
	{
		id = other.id;
		processId = other.processId;
		_pHandle = std::move(other._pHandle);
		suspendCount = other.suspendCount;

		// Release resources to avoid double deletion.
		other.id = 0;
		other.processId = 0;
		other._pHandle = nullptr;
		other.suspendCount = 0;
	}

	// Move constructor.
	Thread::Thread(Thread&& other)
	{
		PerformMove(other);
	}

	// Move assignment.
	Thread& Thread::operator=(Thread&& other)
	{
		if (this != &other)
		{
			PerformMove(other);
		}

		return *this;
	}

	ThreadId Thread::GetId() const
	{
		return id;
	}

	ProcessId Thread::GetProcessId() const
	{
		return processId;
	}

	NT_TIB* Thread::GetTEB32()
	{
		if (GetId() == GetCurrentThreadId())
		{
			return (NT_TIB*)__readfsdword(0x18);
		}

		return (NT_TIB*)GetThreadBasicInformation().TebBaseAddress;
	}

	// TODO May not need this if we can just get the TEB base address from the other function and access that
	//NT_TIB Thread::ReadTEB()
	//{
	//	// TODO Move this to a cached variable
	//	const SmartHandle hProcess = SmartHandle(OpenProcess(PROCESS_VM_READ, FALSE, processId), NULL);
	//	NT_TIB teb;
	//	
	//	MemoryRegion(hProcess, GetTEBBaseAddr(), sizeof(teb)).ReadData(&teb, sizeof(teb));
	//	return teb;
	//}

	void Thread::WriteTEB(const NT_TIB& newTeb)
	{
		// TODO Move this to a cached variable
		const SmartHandle hProcess = SmartHandle(OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId), NULL);

		MemoryRegion(hProcess, GetTEB32(), sizeof(newTeb)).WriteData(&newTeb, sizeof(newTeb));
	}

	bool Thread::IsSuspended()
	{
		DWORD _suspendCount;

		// TODO See header file for an explanation
		if (suspendCount == 0x7FFFFFFF)
		{
			throw std::exception("suspendCount has not been initialized");

			//Suspend();
			// Careful so it doesn't go below 0 and become -1, that's the error code for Suspend and Resume in the WinAPI
			//_suspendCount = suspendCount - 1;
			//Resume();
		}
		else
		{
			_suspendCount = suspendCount;
		}

		return _suspendCount > 0;
	}

	CONTEXT Thread::Suspend(const DWORD contextFlagsToReturn)
	{
		// TODO Ensure handle has permissions THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT
		const auto hThread = GetHandle().GetValue();

		if ((suspendCount = SuspendThread(hThread)) == (DWORD)-1)
		{
			UTIL_THROW_WIN32("SuspendThread failed");
		}

		// SuspendThread is asynchronous so we must block until the thread actually gets suspended.
		// We do this by requesting the thread's context. Raymond says it better than I can:
		// https://blogs.msdn.microsoft.com/oldnewthing/20150205-00/?p=44743

		// TODO THREAD_QUERY_INFORMATION might be required for GetThreadContext() on WOW64, in case this fails
		// TODO Note: need to use Wow64GetThreadContext instead if compiling this program for 64-bit
		CONTEXT threadContext;
		threadContext.ContextFlags = contextFlagsToReturn;

		if (!GetThreadContext(hThread, &threadContext))
		{
			UTIL_THROW_WIN32("GetThreadContext failed");
		}

		return threadContext;
	}

	void Thread::Resume()
	{
		if ((suspendCount = ResumeThread(GetHandle().GetValue())) == (DWORD)-1)
		{
			UTIL_THROW_WIN32("ResumeThread failed");
		}
	}

	void Thread::ForceResume()
	{
		while (IsSuspended())
		{
			Resume();
		}
	}

	void Thread::SetContext(const CONTEXT& newContext)
	{
		// TODO Note that if the thread is inside a syscall when we call SetThreadContext() EAX, ECX and EDX will be trashed (sh!ft's comment: https://www.unknowncheats.me/forum/c-and-c-/170826-setthreadcontext.html).
		// TODO Should verify thread is suspended? Decided not to have "suspended = True" for some reason... It's because someone can update the data while we're suspended?
		if (!SetThreadContext(GetHandle().GetValue(), &newContext))
		{
			UTIL_THROW_WIN32("SetThreadContext failed");
		}
	}

	void* Thread::ChangeEip(void* newEip)
	{
		auto context = Suspend(CONTEXT_CONTROL);

		void* oldEip = (void*)context.Eip;
		context.Eip = (DWORD)newEip;
		SetContext(context);

		Resume();
		return oldEip;
	}

	//void Thread::ChangeStack(void* newStackBase, const DWORD newStackSize)
	//{
	//	// First suspend and then acquire the thread context. We get ESP from CONTEXT_CONTROL and EBP from CONTEXT_INTEGER.
	//	auto context = Suspend(CONTEXT_CONTROL | CONTEXT_INTEGER);

	//	// Update TEB.
	//	auto teb = ReadTEB();
	//	teb.StackBase = (void*)newStackBase;
	//	teb.StackLimit = (char*)newStackBase - newStackSize;
	//	WriteTEB(teb);

	//	// Update ESP and EBP.
	//	void* newEsp = (char*)newStackBase - sizeof(void*);

	//	context.Esp = (DWORD)newEsp;
	//	context.Ebp = (DWORD)newEsp; // TODO Typo? Should be EBP or not?

	//	SetContext(context);

	//	// Resume execution so context changes come into action.
	//	Resume();
	//}

	void Thread::Terminate(const DWORD exitCode, const bool waitUntilTerminated)
	{
		if (!TerminateThread(GetHandle().GetValue(), exitCode))
		{
			UTIL_THROW_WIN32("TerminateThread failed");
		}

		if (waitUntilTerminated)
		{
			WaitFor();
		}
	}

	void Thread::WaitFor()
	{
		if (WaitForSingleObject(GetHandle().GetValue(), INFINITE) == WAIT_FAILED)
		{
			UTIL_THROW_WIN32("WaitForSingleObject failed");
		}
	}

	const SmartHandle& Thread::GetHandle()
	{
		if (!_pHandle)
		{
			// TODO Needs a minimal access specifier/permissions
			_pHandle = std::unique_ptr<SmartHandle>(new SmartHandle(OpenThread(THREAD_ALL_ACCESS, FALSE, id), NULL));
		}

		return *_pHandle;
	}

	Util::Windows::THREAD_BASIC_INFORMATION Thread::GetThreadBasicInformation()
	{
		const HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
		UTIL_ASSERT(hNtdll);

		const auto fpNtQueryInformationThread = (Util::Windows::NativeApi::NtQueryInformationThread)Util::Windows::NativeApi::GetNtdllFuncPtr("NtQueryInformationThread");

		Util::Windows::THREAD_BASIC_INFORMATION threadBasicInformation = { 0 };
		NTSTATUS status = fpNtQueryInformationThread(GetHandle().GetValue(), Util::Windows::ThreadBasicInformation, &threadBasicInformation, sizeof(threadBasicInformation), nullptr);

		if (!Util::Windows::IsNtSuccess(status))
		{
			std::stringstream errorMsg;
			errorMsg << "NtQueryInformationThread failed with status " << std::hex << status;
			throw std::exception(errorMsg.str().c_str());
		}

		return threadBasicInformation;
	}

	void Thread::PinToProcessors(const std::vector<unsigned char>& processorIds)
	{
		if (processorIds.empty())
		{
			throw std::invalid_argument("processorIds can not be an empty list");
		}

		const DWORD maxProcessorId = 8; // Obviously not set in stone.
		DWORD affinityMask = 0;

		for (const auto& processorId : processorIds)
		{
			if (processorId >= maxProcessorId) throw std::invalid_argument("Invalid processor ID");
			affinityMask |= (1 << processorId);
		}

		if (!SetThreadAffinityMask(GetHandle().GetValue(), affinityMask))
		{
			UTIL_THROW_WIN32("SetThreadAffinityMask failed");
		}
	}

	Thread Thread::CreateRemote(const SmartHandle& hProcess, const ProcessId processId, void* startAddress, void* startParameter, const bool waitForThreadToExit)
	{
		DWORD createdThreadId;
		const SmartHandle hThread = SmartHandle(
			CreateRemoteThread(hProcess.GetValue(), NULL, 0, (LPTHREAD_START_ROUTINE)startAddress, startParameter, 0, &createdThreadId),
			NULL
		);

		Thread thread(createdThreadId, processId);

		if (waitForThreadToExit)
		{
			thread.WaitFor();
		}

		return thread;
	}

	DWORD Thread::GetExitCode()
	{
		DWORD exitCode;
		
		if (!GetExitCodeThread(GetHandle().GetValue(), &exitCode))
		{
			UTIL_THROW_WIN32("GetExitCodeThread failed");
		}

		return exitCode;
	}
}