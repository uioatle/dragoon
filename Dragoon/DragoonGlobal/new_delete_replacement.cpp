#include "common.h"
#include "new_delete_replacement.h"

static Util::NativeMemoryAllocator* allocator = NULL;

namespace DragoonGlobal
{
	namespace NewDeleteReplacement
	{
		void SetAllocator(Util::NativeMemoryAllocator* _allocator)
		{
			allocator = _allocator;
		}

		// TODO Call me when cleaning up.
		void ClearAllocator()
		{
			allocator = NULL;
		}
	}
}

/* operator new */

// We're overwriting the operators instead of passing in a custom allocator class to the STL collections. It's global and much safer.
// Should be implemented as shown in the answer by Potatoswatter(?): http://stackoverflow.com/questions/4134195/how-do-i-call-the-original-operator-new-if-i-have-overloaded-it?noredirect=1&lq=1
static NOINLINE void* MyNew(std::size_t n)
{
	void* p;

	if (allocator)
	{
		p = allocator->Malloc(n);
	}
	else
	{
		p = malloc(n);
	}

	if (!p)
	{
		throw std::bad_alloc();
	}

	return p;
}

void* operator new(std::size_t n)
{
	return MyNew(n);
}

void* operator new[](std::size_t n)
{
	return MyNew(n);
}

void* operator new(std::size_t n, const std::nothrow_t& t)
{
	try { return MyNew(n); }
	catch (...) { DragoonGlobal::SafeAbort(); }
}

void* operator new[](std::size_t n, const std::nothrow_t& t)
{
	try { return MyNew(n); }
	catch (...) { DragoonGlobal::SafeAbort(); }
}

/* operator delete */

static NOINLINE void MyDelete(void* p)
{
	if (allocator)
	{
		// As long as the allocator has not been deleted it will always be used first.
		// The allocator will only accept free requests for memory it itself allocated.
		// If it turns down a free request we use the standard free (since we know that
		// means malloc was used to allocate the memory sometime before the allocator was installed).
		if (!allocator->Free(p))
		{
			free(p);
		}
	}
	else
	{
		free(p);
	}
}

void operator delete(void* p)
{
	MyDelete(p);
}

void operator delete[](void* p)
{
	MyDelete(p);
}

void operator delete(void* p, const std::nothrow_t& t)
{
	try { MyDelete(p); }
	catch (...) { DragoonGlobal::SafeAbort(); }
}

void operator delete[](void* p, const std::nothrow_t& t)
{
	try { MyDelete(p); }
	catch (...) { DragoonGlobal::SafeAbort(); }
}