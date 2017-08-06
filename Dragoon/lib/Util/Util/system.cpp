#include "system.h"

namespace Util
{
	void* System::KUSER_SHARED_DATA = (void*)0x7FFE0000;
	void* System::PEB32_Base = (void*)0x7EFDE000;
	void* System::PEB64_Base = (void*)((unsigned char*)System::PEB32_Base + 0x1000);

	const DWORD System::TEB32_Offset = 0x2000;

	const DWORD System::PageSize = 0x1000;
	const DWORD System::AllocationGranularitySize = 0x10000;
}