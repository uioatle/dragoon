#include "lock.h"
#include "windefs.h"

namespace Util
{
	Lock::Lock(const Lock& other)
	{
		isLocked = bool(other.isLocked);
	}

	Lock& Lock::operator=(Lock&& other)
	{
		if (this != &other)
		{
			isLocked = bool(other.isLocked);
			other.isLocked = false;
		}
		return *this;
	}

	bool Lock::TryAcquire()
	{
		// Locking must be atomic to avoid race conditions on the lock variable. This can be achieved
		// by placing '1' (true) into a register and exchanging it with the lock variable. 'xchg' is an
		// atomic x86 instruction. If the value in the register is '1' after the exchange, that means the lock
		// is already taken. Otherwise it was unlocked but has now become locked, so the operation was atomic.
		// We can leverage C++11 to do this without assembly using the <atomic> data type.
		const bool wasLockAcquired = !isLocked.exchange(true);
		return wasLockAcquired;
	}

	void Lock::Acquire()
	{
		while (!TryAcquire()) Util::Windows::NativeApi::YieldTimeSlice();
		return;
	}

	void Lock::Release()
	{
		isLocked = false;
	}

	bool Lock::IsLocked() const
	{
		return isLocked;
	}
}