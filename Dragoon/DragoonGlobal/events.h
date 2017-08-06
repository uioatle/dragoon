#pragma once

namespace DragoonGlobal
{
	namespace Events
	{
		enum class EventCodes : unsigned char
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
	}
}