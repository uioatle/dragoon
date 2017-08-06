#pragma once

#include "lib\Util\include\native_memory_allocator.h"

namespace DragoonGlobal
{
	namespace NewDeleteReplacement
	{
		void SetAllocator(Util::NativeMemoryAllocator* allocator);
		void ClearAllocator();
	}
}