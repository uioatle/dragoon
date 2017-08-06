#pragma once

#include <stdexcept>
#include <Windows.h>

namespace Util
{
	/*
	Handle that automatically closes itself.
	*/
	class SmartHandle
	{
	public:
		SmartHandle() = default;
		SmartHandle(HANDLE handle, HANDLE invalidHandleValue);

		SmartHandle(const SmartHandle& other) = delete;
		SmartHandle& operator=(const SmartHandle& other) = delete;

		SmartHandle(SmartHandle&& other);
		SmartHandle& operator=(SmartHandle&& other);

		~SmartHandle();

		HANDLE GetValue() const;
		bool IsValid() const;
		void Close();
	private:
		static const HANDLE uninitializedHandleValue;

		HANDLE handle = uninitializedHandleValue;
		HANDLE invalidHandleValue = uninitializedHandleValue;

		void Set(HANDLE handle, HANDLE invalidHandleValue, bool throwIfInvalid = true);
	};
}