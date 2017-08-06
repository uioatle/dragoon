#include "lib\Util\include\smart_handle.h"
#include "lib\Util\include\dll_injection.h"
#include "lib\Util\include\thread.h"
#include "lib\Util\include\module.h"

#include "DragoonGlobal\common.h"

#include <iostream>
#include <string>
#include <utility>
#include <Windows.h>

namespace Dragoon
{
	std::pair<PROCESS_INFORMATION, DEBUG_EVENT> SpawnTargetApplicationInDebugMode(const std::string& targetAppPath)
	{
		STARTUPINFOA startupInfo;
		PROCESS_INFORMATION processInfo;
		ZeroMemory(&startupInfo, sizeof(startupInfo));
		ZeroMemory(&processInfo, sizeof(processInfo));
		startupInfo.cb = sizeof(startupInfo);

		// TODO Process and thread handles should not be set uninheritable? What if the process spawns a subprocess later etc.?
		// TODO Debugged application must be able to be started with arguments, e.g. recording a debugger debugging another program
		if (!CreateProcessA(targetAppPath.c_str(), NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &startupInfo, &processInfo))
		{
			UTIL_THROW_WIN32("Failed to spawn target application process");
		}

		// Wait for CREATE_PROCESS_DEBUG_EVENT.
		DEBUG_EVENT debugEvent;

		if (!WaitForDebugEvent(&debugEvent, INFINITE))
		{
			UTIL_THROW_WIN32("WaitForDebugEvent failed");
		}

		if (debugEvent.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT)
		{
			throw new std::runtime_error("First debug event was not CREATE_PROCESS_DEBUG_EVENT");
		}

		return std::make_pair(processInfo, debugEvent);
	}
	
	void DetachDebugger(const DEBUG_EVENT debugEvent)
	{
		CloseHandle(debugEvent.u.CreateProcessInfo.hFile);

		if (!DebugActiveProcessStop(debugEvent.dwProcessId))
		{
			UTIL_THROW_WIN32("Failed to detach debugger");
		}
	}

	void Start(const std::string& targetAppPath, const bool recordFromBeginning)
	{
		// Spawn the target application as a process and wait in a suspended (debugged) state at its entry point.
		const std::pair<PROCESS_INFORMATION, DEBUG_EVENT> spawnedProcessInfo = SpawnTargetApplicationInDebugMode(targetAppPath);

		const Util::SmartHandle hSpawnedProcess(spawnedProcessInfo.first.hProcess, NULL);
		Util::Thread spawnedProcessMainThread(spawnedProcessInfo.first.dwThreadId, spawnedProcessInfo.first.dwProcessId);

		// Since the debuggee is being debugged it's not running, but it's still not suspended!
		// When we detach the debugger it will start running again so we need to suspend it before we do that.
		spawnedProcessMainThread.Suspend();
		DetachDebugger(spawnedProcessInfo.second);

		// -------------------------------------------------------------------------------------------

		// Inject DragoonDll into the target process.
		void* dragoonDllBaseAddr = Util::InjectDll(hSpawnedProcess, DragoonGlobal::Paths::dragoonDll);
		Util::Module dragoonDll(hSpawnedProcess, dragoonDllBaseAddr);

		// Run DragoonDll#Init.
		if (Util::Thread::CreateRemote(
			hSpawnedProcess,
			spawnedProcessInfo.first.dwProcessId,
			dragoonDll.GetExportedSymbolByName("Init").addr,
			NULL
		).GetExitCode() != 0) {
			throw std::runtime_error("DragoonDll#Init returned error code");
		}

		if (recordFromBeginning)
		{
			// Start recording right away from the entry point.
			if (Util::Thread::CreateRemote(
				hSpawnedProcess,
				spawnedProcessInfo.first.dwProcessId,
				dragoonDll.GetExportedSymbolByName("StartRecording").addr,
				(void*)spawnedProcessMainThread.GetId() // Passing in thread ID of main thread (which is suspended)
			).GetExitCode() != 0)
			{
				throw std::runtime_error("DragoonDll#StartRecording returned error code");
			}
		}
		else
		{
			spawnedProcessMainThread.Resume();
		}

		// TODO Remove, it's only there to avoid the exception I didn't fix yet.
		printf("TODO Exiting Dragoon loader prematurely to avoid exception stack trace...\n");
		return;

		// -------------------------------------------------------------------------------------------

		// Close the handles of the spawned process received from CreateProcess.
		CloseHandle(spawnedProcessInfo.first.hProcess);
		CloseHandle(spawnedProcessInfo.first.hThread);
	}
}