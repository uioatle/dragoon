#pragma once

#include <cstdint>

namespace Util
{
	template<uint32_t N, typename T>
	class FastBitsetMap
	{
	public:
		FastBitsetMap();
		void Set(uint32_t index, T value);
		void Clear(uint32_t index);
		bool Test(uint32_t index) const;
		T& Get(uint32_t index);
		uint32_t GetSize() const;
		void Reset();
	private:
		struct Record
		{
			bool isSet;
			T value;
		};

		Record arr[N];
	};

	template<uint32_t N, typename T>
	__declspec(noinline) FastBitsetMap<N, T>::FastBitsetMap()
	{
		Reset();
	}

	template<uint32_t N, typename T>
	__declspec(noinline) void FastBitsetMap<N, T>::Set(const uint32_t index, const T value)
	{
		Record& record = arr[index];
		record.isSet = true;
		record.value = value;
	}

	template<uint32_t N, typename T>
	__declspec(noinline) void FastBitsetMap<N, T>::Clear(const uint32_t index)
	{
		arr[index].isSet = false;
	}

	template<uint32_t N, typename T>
	__declspec(noinline) bool FastBitsetMap<N, T>::Test(const uint32_t index) const
	{
		return arr[index].isSet;
	}

	template<uint32_t N, typename T>
	__declspec(noinline) T& FastBitsetMap<N, T>::Get(const uint32_t index)
	{
		return arr[index].value;
	}

	template<uint32_t N, typename T>
	__declspec(noinline) uint32_t FastBitsetMap<N, T>::GetSize() const
	{
		return N;
	}

	template<uint32_t N, typename T>
	__declspec(noinline) void FastBitsetMap<N, T>::Reset()
	{
		for (uint32_t i = 0; i < N; ++i)
		{
			arr[i].isSet = false;
		}
	}
}