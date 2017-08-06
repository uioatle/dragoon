#include "module.h"
#include "memory_region.h"
#include "common.h"
#include <memory>
#include <unordered_map>

namespace Util
{
	Module::Module(const SmartHandle& hProcess, void* baseAddr) : hProcess(hProcess), baseAddr(baseAddr) {}

	IMAGE_NT_HEADERS Module::GetNtHeaders()
	{
		const bool imageNtHeadersMemberIsInitialized = imageNtHeaders.Signature == IMAGE_NT_SIGNATURE;
		if (!imageNtHeadersMemberIsInitialized)
		{
			IMAGE_DOS_HEADER imageDosHeader;
			MemoryRegion(hProcess, baseAddr, sizeof(imageDosHeader)).ReadData(&imageDosHeader, sizeof(imageDosHeader));
			UTIL_ASSERT(imageDosHeader.e_magic == IMAGE_DOS_SIGNATURE);

			IMAGE_NT_HEADERS imageNtHeaders;
			MemoryRegion(hProcess, (unsigned char*)baseAddr + imageDosHeader.e_lfanew, sizeof(imageNtHeaders)).ReadData(&imageNtHeaders, sizeof(imageNtHeaders));
			UTIL_ASSERT(imageNtHeaders.Signature == IMAGE_NT_SIGNATURE);

			this->imageNtHeaders = imageNtHeaders;
		}
		return imageNtHeaders;
	}

	void* Module::GetBaseAddress() const
	{
		return baseAddr;
	}

	void* Module::GetEntryPoint()
	{
		return (unsigned char*)baseAddr + GetNtHeaders().OptionalHeader.AddressOfEntryPoint;
	}

	std::vector<Module::ExportedSymbol> Module::GetExportedSymbols()
	{
		if (isExportedSymbolsMemberInitialized)
		{
			return exportedSymbols;
		}

		const auto imageNtHeaders = GetNtHeaders();

		// Retrieve export directory.
		UTIL_ASSERT(imageNtHeaders.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT);
		const void* exportDirRva = (void*)imageNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		// No exports?
		if (exportDirRva == 0)
		{
			return std::vector<Module::ExportedSymbol>();
		}

		IMAGE_EXPORT_DIRECTORY imageExportDirectory;
		MemoryRegion(hProcess, (unsigned char*)baseAddr + (DWORD)exportDirRva, sizeof(imageExportDirectory)).ReadData(&imageExportDirectory, sizeof(imageExportDirectory));

		// Retrieve exported names.
		const DWORD namesSizeInBytes = sizeof(char*) * imageExportDirectory.NumberOfNames;
		const auto names = std::unique_ptr<unsigned char[]>(new unsigned char[namesSizeInBytes]);

		UTIL_ASSERT(imageExportDirectory.AddressOfNames);
		MemoryRegion(
			hProcess,
			(unsigned char*)baseAddr + imageExportDirectory.AddressOfNames,
			namesSizeInBytes
		).ReadData(names.get(), namesSizeInBytes);

		std::vector<std::string> nameList;

		for (DWORD i = 0; i < imageExportDirectory.NumberOfNames; i++)
		{
			const USHORT maxWinExportNameLength = 0x1000;
			std::string name(maxWinExportNameLength, '\0');
			MemoryRegion(hProcess, (unsigned char*)baseAddr + ((DWORD*)names.get())[i], name.size()).ReadData((void*)name.data(), name.size());
			name.resize(strlen(name.data()));
			name.shrink_to_fit(); // Also reduce capacity to the new size.

			// Add the string to the list.
			nameList.push_back(name);
		}

		// Retrieve name ordinals.
		const DWORD nameOrdinalsSizeInBytes = sizeof(USHORT) * imageExportDirectory.NumberOfNames;
		const auto nameOrdinals = std::unique_ptr<unsigned char[]>(new unsigned char[nameOrdinalsSizeInBytes]);

		UTIL_ASSERT(imageExportDirectory.AddressOfNameOrdinals);
		MemoryRegion(
			hProcess,
			(unsigned char*)baseAddr + imageExportDirectory.AddressOfNameOrdinals,
			nameOrdinalsSizeInBytes
		).ReadData(nameOrdinals.get(), nameOrdinalsSizeInBytes);

		std::unordered_map<DWORD, std::string*> ordinalToNameMap;
		for (DWORD i = 0; i < imageExportDirectory.NumberOfNames; i++)
		{
			ordinalToNameMap[((USHORT*)nameOrdinals.get())[i]] = &nameList.at(i);
		}

		// Retrieve function addresses.
		const DWORD functionsSizeInBytes = sizeof(DWORD) * imageExportDirectory.NumberOfFunctions;
		const auto functions = std::unique_ptr<unsigned char[]>(new unsigned char[functionsSizeInBytes]);

		UTIL_ASSERT(imageExportDirectory.AddressOfFunctions);
		MemoryRegion(
			hProcess,
			(unsigned char*)baseAddr + imageExportDirectory.AddressOfFunctions,
			functionsSizeInBytes
		).ReadData(functions.get(), functionsSizeInBytes);

		for (DWORD i = 0; i < imageExportDirectory.NumberOfFunctions; i++)
		{
			ExportedSymbol exportedSymbol;

			exportedSymbol.ordinal = i + 1;
			exportedSymbol.name = ordinalToNameMap.count(i) ? *ordinalToNameMap[i] : std::string();
			exportedSymbol.addr = (unsigned char*)baseAddr + ((DWORD*)functions.get())[i];

			exportedSymbols.push_back(exportedSymbol);
		}

		isExportedSymbolsMemberInitialized = true;
		return exportedSymbols;
	}

	Module::ExportedSymbol Module::GetExportedSymbolByName(const std::string& name)
	{
		for (const auto& exportedSymbol : GetExportedSymbols())
		{
			if (!exportedSymbol.name.empty() && exportedSymbol.name == name)
			{
				return exportedSymbol;
			}
		}

		throw std::exception(("Requested export '" + name + "' not found").c_str());
	}
}