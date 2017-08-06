#include "logging.h"

#include "common.h"
#include "paths.h"

#include "lib/Util/include/windefs.h"
#include "lib/Util/include/smart_handle.h"

#include <iostream>
#include <sstream>

namespace DragoonGlobal { namespace Logging
{
	Util::Windows::NativeApi::NtWriteFile fpNtWriteFile;
	Util::SmartHandle* hLogFile;

	NOINLINE void Init()
	{
		// TODO Disabled until further notice.
		return;

		fpNtWriteFile = (Util::Windows::NativeApi::NtWriteFile)Util::Windows::NativeApi::GetNtdllFuncPtr("NtWriteFile");

		std::stringstream ss;
		ss << DragoonGlobal::Paths::cwd << "log.txt";
		const std::string filePath = ss.str();
		hLogFile = new Util::SmartHandle(CreateFileA(filePath.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL), INVALID_HANDLE_VALUE);
	}

	NOINLINE void Terminate()
	{
		// TODO Disabled until further notice.
		return;

		if (hLogFile)
		{
			hLogFile->Close();
		}
	}

	NOINLINE void Log(const char* message, const uint32_t length)
	{
		// The string buffer to be logged was freed by RtlHeapFree(), and then havoc ensued. Just disable logging for now to avoid this kind of <bad word>.
		__asm int 3;
		__asm int 2;

		Util::Windows::IO_STATUS_BLOCK iosb;
		const NTSTATUS status = fpNtWriteFile(hLogFile->GetValue(), NULL, NULL, NULL, &iosb, (PVOID)message, length, NULL, NULL);

		if (!Util::Windows::IsNtSuccess(status))
		{
			DragoonGlobal::SafeAbort();
		}
	}

	NOINLINE void Log(const std::string& message)
	{
		Log(message.c_str(), message.length());
	}
}}