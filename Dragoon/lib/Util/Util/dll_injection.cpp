#include "dll_injection.h"
#include "common.h"
#include "memory_region.h"
#include "thread.h"

namespace Util
{
	// Process handle must have permissions:
	// PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
	HMODULE Util::InjectDll(const SmartHandle& hProcess, const std::string& dllPath)
	{
		// Retrieve address of kernel32#LoadLibraryA.
		void* loadLibraryAAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		if (!loadLibraryAAddr) UTIL_THROW_WIN32("Failed to retrieve address of LoadLibraryA");

		// Allocate memory in target process. Write DLL path to it (including null terminator).
		MemoryRegion allocatedMem(hProcess, NULL, dllPath.length() + 1);
		allocatedMem.Allocate(MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		allocatedMem.WriteData(dllPath.c_str(), allocatedMem.GetSizeAtConstruction(), false);

		// Create remote thread in target process at the address of LoadLibraryA (kernel32 is located at the same base address in all processes).
		// Pass it the address of the allocated memory which holds the DLL path as parameter. This will load the DLL into the process.
		Thread thread = Thread::CreateRemote(hProcess, GetProcessId(hProcess.GetValue()), loadLibraryAAddr, allocatedMem.GetBaseAddr());

		// Free the memory allocated for the DLL path.
		MemoryRegion::Free(hProcess, allocatedMem.GetBaseAddr());

		// Return the injected DLL's base address returned from the LoadLibraryA call.
		const auto threadExitCode = thread.GetExitCode();
		UTIL_ASSERT(threadExitCode != NULL);
		return (HMODULE)threadExitCode;
	}
}