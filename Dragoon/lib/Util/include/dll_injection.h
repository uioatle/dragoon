#pragma once

#include "smart_handle.h"
#include <string>
#include <Windows.h>

namespace Util
{
	HMODULE InjectDll(const SmartHandle& hProcess, const std::string& dllPath);
}