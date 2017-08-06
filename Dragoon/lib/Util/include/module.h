#pragma once

#include "smart_handle.h"
#include <string>
#include <vector>
#include <Windows.h>

namespace Util
{
	class Module
	{
	public:
		struct ExportedSymbol
		{
			DWORD ordinal;
			std::string name;
			void* addr;
		};

		Module(const SmartHandle& hProcess, void* baseAddr);

		void* GetBaseAddress() const;
		void* GetEntryPoint();
		std::vector<ExportedSymbol> GetExportedSymbols();
		ExportedSymbol GetExportedSymbolByName(const std::string& name);
	private:
		const SmartHandle& hProcess;
		void* baseAddr;

		IMAGE_NT_HEADERS imageNtHeaders;

		bool isExportedSymbolsMemberInitialized = false;
		std::vector<ExportedSymbol> exportedSymbols;

		IMAGE_NT_HEADERS GetNtHeaders();
	};
}