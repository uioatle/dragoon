#include <fstream>
#include <iostream>
#include <iomanip>
#include <cstdio>
#include <memory>

/* Credit: Steve Karg */
/* a=target variable, b=bit number to act upon 0-n */
#define BIT_SET(a,b) ((a) |= (1<<(b)))
#define BIT_CLEAR(a,b) ((a) &= ~(1<<(b)))
#define BIT_FLIP(a,b) ((a) ^= (1<<(b)))
#define BIT_CHECK(a,b) ((a) & (1<<(b)))
/* x=target variable, y=mask */
#define BITMASK_SET(x,y) ((x) |= (y))
#define BITMASK_CLEAR(x,y) ((x) &= (~(y)))
#define BITMASK_FLIP(x,y) ((x) ^= (y))
#define BITMASK_CHECK(x,y) (((x) & (y)) == (y))
/* ----- */

enum EventCodes : unsigned char
{
	/* Aggregate events */
	SyscallEvent,
	ExceptionEvent,
	MemoryAllocationAddedEvent,

	/* Sub-events */
	MemoryRegionAddedEvent,
	MemoryAllocationRemovedEvent,
	MemoryModifiedEvent,
	RdtscEvent,
	ContextModifiedEvent
};

enum ContextModifiedEventBitmapRegisterIndices : unsigned char
{
	EAX = 0,
	ECX = 1,
	EDX = 2
};

void printBytes(const unsigned char* data, const uint32_t numBytesToPrint, std::ofstream& outFile)
{
	outFile << std::hex << std::setfill('0');

	for (uint32_t i = 0; i < numBytesToPrint; ++i)
	{
		outFile << std::setw(2) << static_cast<unsigned int>(data[i]) << " ";
	}
}

void handleMemoryRegionAddedEvent(std::ifstream& file, std::ofstream& outFile)
{
	void* baseAddr;
	void* allocationBase;
	unsigned int regionSize;
	unsigned int regionProtection;
	unsigned int regionState;
	auto data = std::unique_ptr<unsigned char>(new unsigned char[0x1000 * 100000]);

	file.read((char*)&baseAddr, sizeof(baseAddr));
	file.read((char*)&allocationBase, sizeof(allocationBase));
	file.read((char*)&regionSize, sizeof(regionSize));
	file.read((char*)&regionProtection, sizeof(regionProtection));
	file.read((char*)&regionState, sizeof(regionState));
	file.read((char*)data.get(), regionSize);

	outFile << "<MemoryRegionAllocatedEvent> BaseAddr: " << std::hex << baseAddr << ", AllocationBase: " << allocationBase << ", RegionSize: " << regionSize << ", RegionProtection: " << regionProtection << ", RegionState: " << regionState << ", Bytes: ";

	printBytes(data.get(), 0x1000, outFile);
	if (regionSize > 0x1000)
	{
		outFile << "[...]";
	}

	outFile << std::endl;
}

void handleMemoryAllocationRemovedEvent(std::ifstream& file, std::ofstream& outFile)
{
	void* allocationBase;
	file.read((char*)&allocationBase, sizeof(allocationBase));

	outFile << "<MemoryAllocationRemovedEvent> AllocationBase: " << std::hex << allocationBase << std::endl;
}

void handleMemoryModifiedEvent(std::ifstream& file, std::ofstream& outFile)
{
	void* addr;
	unsigned int size;
	auto data = std::unique_ptr<unsigned char>(new unsigned char[0x1000 * 100000]);

	file.read((char*)&addr, sizeof(addr));
	file.read((char*)&size, sizeof(size));
	file.read((char*)data.get(), size);

	outFile << "<MemoryModifiedEvent> Addr: " << std::hex << addr << ", Size: " << size << ", Bytes: ";
	printBytes(data.get(), size, outFile);
	outFile << std::endl;
}

void handleRdtscEvent(std::ifstream& file, std::ofstream& outFile)
{
	unsigned int eax;
	unsigned int edx;
	file.read((char*)&eax, sizeof(eax));
	file.read((char*)&edx, sizeof(edx));

	outFile << "<RdtscEvent> Eax: " << std::hex << eax << ", Edx: " << edx << std::endl;
}

void handleContextModifiedEvent(std::ifstream& file, std::ofstream& outFile)
{
	unsigned char registersToDumpBitmap;
	file.read((char*)&registersToDumpBitmap, sizeof(registersToDumpBitmap));

	outFile << "<ContextModifiedEvent> Bitmap: " << std::hex << static_cast<unsigned>(registersToDumpBitmap);

	if (BIT_CHECK(registersToDumpBitmap, ContextModifiedEventBitmapRegisterIndices::EAX))
	{
		unsigned int eax;
		file.read((char*)&eax, sizeof(eax));
		outFile << ", Eax: " << eax;
	}
	if (BIT_CHECK(registersToDumpBitmap, ContextModifiedEventBitmapRegisterIndices::ECX))
	{
		unsigned int ecx;
		file.read((char*)&ecx, sizeof(ecx));
		outFile << ", Ecx: " << ecx;
	}
	if (BIT_CHECK(registersToDumpBitmap, ContextModifiedEventBitmapRegisterIndices::EDX))
	{
		unsigned int edx;
		file.read((char*)&edx, sizeof(edx));
		outFile << ", Edx: " << edx;
	}

	outFile << std::endl;
}

void handleUnsupportedSubEvent(std::ifstream& file, unsigned char subEventCode)
{
	std::cout << "Unknown subEventCode " << static_cast<unsigned>(subEventCode) << " at file position " << file.tellg() << ". Aborting..." << std::endl;
	abort();
}

bool isEventCodeSubEvent(const unsigned char eventCode)
{
	return eventCode >= EventCodes::MemoryRegionAddedEvent;
}

void handleSubEvents(std::ifstream& file, std::ofstream& outFile)
{
	while (true)
	{
		unsigned char subEventCode = file.peek();

		if (file.eof() || !isEventCodeSubEvent(subEventCode))
		{
			return;
		}

		file.ignore();

		printf("SubEventCode: %02X\n", subEventCode);

		switch (subEventCode)
		{
		case EventCodes::MemoryRegionAddedEvent:
			handleMemoryRegionAddedEvent(file, outFile);
			break;
		case EventCodes::MemoryAllocationRemovedEvent:
			handleMemoryAllocationRemovedEvent(file, outFile);
			break;
		case EventCodes::MemoryModifiedEvent:
			handleMemoryModifiedEvent(file, outFile);
			break;
		case EventCodes::RdtscEvent:
			handleRdtscEvent(file, outFile);
			break;
		case EventCodes::ContextModifiedEvent:
			handleContextModifiedEvent(file, outFile);
			break;
		default:
			handleUnsupportedSubEvent(file, subEventCode);
			break;
		}
	}
}

void handleSyscallEvent(std::ifstream& file, std::ofstream& outFile)
{
	unsigned short syscallIndex;
	file.read((char*)&syscallIndex, sizeof(syscallIndex));

	printf("SyscallEvent: %04X\n", syscallIndex);

	outFile << "<Syscall> Index: " << std::hex << syscallIndex << std::endl;

	handleSubEvents(file, outFile);
}

void handleExceptionEvent(std::ifstream& file)
{
	std::cout << "ExceptionEvent not implemented. Found at position " << file.tellg() << ". Aborting..." << std::endl;
	abort();
}

void handleMemoryAllocationAddedEvent(std::ifstream& file, std::ofstream& outFile)
{
	unsigned int allocationSize;
	file.read((char*)&allocationSize, sizeof(allocationSize));

	outFile << "<MemoryAllocationAddedEvent> Allocation size: " << std::hex << allocationSize << std::endl;

	handleSubEvents(file, outFile);
}

void handleUnsupportedEvent(std::ifstream& file, unsigned char eventCode)
{
	std::cout << "Unknown event code " << std::hex << static_cast<unsigned>(eventCode) << " at file position " << file.tellg() << ". Aborting... " << std::endl;
	abort();
}

int main(int argc, char** argv)
{
	std::ifstream file("X:/Dragoon/recording/1224.tel", std::ios::binary);
	std::ofstream outFile("C:/Code/Projects/Dragoon/event_log.txt");

	if (!file)
	{
		std::cout << "Failed to open infile" << std::endl;
		abort();
	}

	if (!outFile)
	{
		std::cout << "Failed to open outfile" << std::endl;
		abort();
	}

	while (!file.eof())
	{
		unsigned char eventCode = file.peek();
		file.ignore();

		printf("EventCode: %02X\n", eventCode);

		switch (eventCode)
		{
		case EventCodes::SyscallEvent:
			handleSyscallEvent(file, outFile);
			break;
		case EventCodes::ExceptionEvent:
			handleExceptionEvent(file);
			break;
		case EventCodes::MemoryAllocationAddedEvent:
			handleMemoryAllocationAddedEvent(file, outFile);
			break;
		default:
			handleUnsupportedEvent(file, eventCode);
			break;
		}

		outFile << std::endl;
	}

	return 0;
}