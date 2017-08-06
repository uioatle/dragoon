#pragma once

#include <atomic>

namespace Util
{
	class Lock
	{
	public:
		Lock() = default;

		Lock(const Lock& other);
		Lock& operator=(const Lock& other) = delete;

		Lock(Lock&& other) = delete;
		Lock& operator=(Lock&& other);

		void Acquire();
		void Release();
		bool IsLocked() const;
	private:
		std::atomic<bool> isLocked = false;

		bool TryAcquire();
	};
}