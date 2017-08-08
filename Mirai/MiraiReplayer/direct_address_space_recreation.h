#ifndef MIRAI_DIRECT_ADDRESS_SPACE_RECREATION_H
#define MIRAI_DIRECT_ADDRESS_SPACE_RECREATION_H

#include "shared.h"
#include "smart_handle.h"
#include "thread.h"

typedef struct
{
	Util::ProcessId replayProcessId;
	Util::ThreadId waitingThreadId;
	void* replayerDllBaseAddr;
	void* nextBlockAddr;
} DirectlyRecreateAddressSpaceReturnValues;

DirectlyRecreateAddressSpaceReturnValues directlyRecreateAddressSpace(const RecordedMemRegionsFromDisk& recordedMemRegionsFromDisk);

#endif