#ifndef MIRAI_SHARED_H
#define MIRAI_SHARED_H

#include <vector>
#include <memory>
#include <Windows.h>

#define int3break() __asm nop

bool hasSuffix(const std::wstring& str, const std::wstring& suffix);

// TODO Make it not hardcoded
const std::wstring cwd = L"C:\\Code\\Projects\\Mirai\\Release\\";
const std::wstring recordingDir = cwd + L"recording\\";
const std::wstring memoryDumpDir = recordingDir + L"memory_dump\\";

struct RecordedMemoryRegion
{
	MEMORY_BASIC_INFORMATION header;
	std::unique_ptr<unsigned char[]> data;
	uint32_t dataSize;

	RecordedMemoryRegion(const uint32_t dataSize) : dataSize(dataSize)
	{
		if (dataSize > 0) {
			data = std::unique_ptr<unsigned char[]>(new unsigned char[dataSize]);
		}
	}

	bool containsData(void) const
	{
		return dataSize != 0;
	}
};

struct RecordedMemRegionsFromDisk
{
	std::shared_ptr<RecordedMemoryRegion> pebRegion;
	std::vector<std::shared_ptr<RecordedMemoryRegion>> tebRegions;
	std::vector<std::shared_ptr<RecordedMemoryRegion>> memRegions;
};

RecordedMemRegionsFromDisk loadRecordedMemoryRegionsFromDisk();

#endif