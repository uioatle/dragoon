#pragma once

#include <cstdint>

namespace Util
{
	template<uint32_t N>
	class FastBitset
	{
	public:
		FastBitset();
		void Set(uint32_t index);
		void Clear(uint32_t index);
		bool Test(uint32_t index) const;
		uint32_t GetSize() const;
		void Reset();
	private:
		unsigned char arr[N];
	};

	template<uint32_t N>
	__declspec(noinline) FastBitset<N>::FastBitset() : arr() // zero-initialize array
	{
	}

	template<uint32_t N>
	__declspec(noinline) void FastBitset<N>::Set(uint32_t index)
	{
		arr[index] = 1;
	}

	template<uint32_t N>
	__declspec(noinline) void FastBitset<N>::Clear(uint32_t index)
	{
		arr[index] = 0;
	}

	template<uint32_t N>
	__declspec(noinline) bool FastBitset<N>::Test(uint32_t index) const
	{
		return arr[index] == 1;
	}

	template<uint32_t N>
	__declspec(noinline) uint32_t FastBitset<N>::GetSize() const
	{
		return N;
	}

	template<uint32_t N>
	__declspec(noinline) void FastBitset<N>::Reset()
	{
		memset(&arr, 0, sizeof(arr));
	}
}