#pragma once

#include <string>
#include <cstdint>

namespace DragoonGlobal { namespace Logging
{
	void Init();
	void Terminate();

	void Log(const char* message, uint32_t length);
	void Log(const std::string& message);
}}