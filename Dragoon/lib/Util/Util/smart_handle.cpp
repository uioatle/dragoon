#include "smart_handle.h"
#include "common.h"

namespace Util
{
	// -1 is a pseudohandle, used amongst other things as return value from GetCurrentProcess(), so can't use that.
	const HANDLE SmartHandle::uninitializedHandleValue = (HANDLE)-2;

	SmartHandle::SmartHandle(const HANDLE handle, const HANDLE invalidHandleValue)
	{
		Set(handle, invalidHandleValue);
	}

	SmartHandle::SmartHandle(SmartHandle&& other)
	{
		handle = other.handle;
		invalidHandleValue = other.invalidHandleValue;
		
		other.handle = uninitializedHandleValue;
		other.invalidHandleValue = uninitializedHandleValue;
	}

	SmartHandle& SmartHandle::operator=(SmartHandle&& other)
	{
		if (this != &other)
		{
			handle = other.handle;
			invalidHandleValue = other.invalidHandleValue;

			other.handle = uninitializedHandleValue;
			other.invalidHandleValue = uninitializedHandleValue;
		}
		return *this;
	}

	SmartHandle::~SmartHandle()
	{
		Close();
	}

	void SmartHandle::Set(const HANDLE handle, const HANDLE invalidHandleValue, const bool throwIfInvalid)
	{
		this->handle = handle;
		this->invalidHandleValue = invalidHandleValue;

		if (throwIfInvalid && !IsValid())
		{
			this->handle = uninitializedHandleValue;
			this->invalidHandleValue = uninitializedHandleValue;
			throw std::invalid_argument("The handle used to initialize the object is not a valid handle");
		}
	}

	HANDLE SmartHandle::GetValue() const
	{
		if (handle == uninitializedHandleValue)
		{
			throw std::exception("Handle value not initialized");
		}

		return handle;
	}

	bool SmartHandle::IsValid() const
	{
		return handle != uninitializedHandleValue && handle != invalidHandleValue;
	}

	void SmartHandle::Close()
	{
		const bool isPseudoHandle = handle == (HANDLE)-1;

		if (IsValid() && !isPseudoHandle)
		{
			if (!CloseHandle(handle))
			{
				UTIL_THROW_WIN32("CloseHandle failed");
			}

			handle = invalidHandleValue;
		}
	}
}