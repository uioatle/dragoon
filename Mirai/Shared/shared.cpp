#include "shared.h"
#include "common.h"

#include <fstream>

// Credit: Dietrich Epp (http://stackoverflow.com/questions/20446201/how-to-check-if-string-ends-with-txt).
bool hasSuffix(const std::wstring& str, const std::wstring& suffix)
{
	return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

RecordedMemRegionsFromDisk loadRecordedMemoryRegionsFromDisk()
{
	RecordedMemRegionsFromDisk recordedMemRegionsFromDisk;

	for (const auto& fileName : Util::GetFileNamesInDirectory(memoryDumpDir)) {
		// Read memory region dump file into memory.
		const std::wstring memoryRegionDumpFileName = memoryDumpDir + fileName;

		// Open the file at the end so we can get its size right away.
		std::ifstream memoryRegionDumpFile(memoryRegionDumpFileName, std::ios::binary | std::ios::ate);
		if (!memoryRegionDumpFile) {
			continue;
		}

		const DWORD fileSize = memoryRegionDumpFile.tellg();
		memoryRegionDumpFile.seekg(0);

		const DWORD dataSize = fileSize - sizeof(MEMORY_BASIC_INFORMATION);
		std::shared_ptr<RecordedMemoryRegion> recordedMemoryRegion(new RecordedMemoryRegion(dataSize));

		memoryRegionDumpFile.read((char*)&recordedMemoryRegion->header, sizeof(MEMORY_BASIC_INFORMATION));

		// Memory region.
		if (recordedMemoryRegion->header.State == MEM_COMMIT) {
			if (dataSize == 0) {
				memoryRegionDumpFile.close();
				printf("Failed to read memory region contents from file. No data exists (data size = 0)\n");
				throw std::exception("Check last printf()");
			}

			memoryRegionDumpFile.read((char*)recordedMemoryRegion->data.get(), dataSize);
		}

		memoryRegionDumpFile.close();

		if (hasSuffix(memoryRegionDumpFileName, L".peb_region"))
		{
			recordedMemRegionsFromDisk.pebRegion = recordedMemoryRegion;
		}
		else if (hasSuffix(memoryRegionDumpFileName, L".teb_region"))
		{
			recordedMemRegionsFromDisk.tebRegions.push_back(recordedMemoryRegion);
		}
		else
		{
			recordedMemRegionsFromDisk.memRegions.push_back(recordedMemoryRegion);
		}
	}

	util_assert(!recordedMemRegionsFromDisk.memRegions.empty());
	util_assert(!recordedMemRegionsFromDisk.tebRegions.empty());
	util_assert(recordedMemRegionsFromDisk.pebRegion != NULL); // TODO The struct member is probably initialized to something other than NULL

	return recordedMemRegionsFromDisk;
}