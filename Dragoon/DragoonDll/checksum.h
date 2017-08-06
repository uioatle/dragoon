#pragma once

#include "DragoonGlobal\common.h"

#include "xxhash.h"

#include <cstdint>
#include <nmmintrin.h>

#define EM(a) __asm __emit (a)

/* SSE4.2 CRC32 versions */

// Warning! Not padding, so don't use if length isn't dividable by sizeof(uint32_t).
uint32_t sse42_crc32_32bit(const uint32_t* buffer, const uint32_t length)
{
	uint32_t crc = 0;
	const uint32_t numRounds = length / sizeof(uint32_t);

	for (uint32_t i = 0; i < numRounds; ++i)
	{
		crc = _mm_crc32_u32(crc, buffer[i]);
	}

	return crc;
}

/*
<64-bit crc32 in hardware>

C++ code:

// Warning! Not padding, so don't use if length isn't dividable by sizeof(uint64_t).
__declspec(noinline) uint32_t sse42_crc32_64bit(const uint32_t* _buffer, const uint32_t length)
{
	// TODO See if it runs faster by using 64-bit data types instead of 32-bit

	// Taking 32-bit pointer for 32-bit compatibility.
	const uint64_t* buffer = reinterpret_cast<const uint64_t*>(_buffer);

	uint32_t crc = 0;
	const uint32_t numRounds = length / sizeof(uint64_t);

	for (uint32_t i = 0; i < numRounds; ++i)
	{
	crc = _mm_crc32_u64(crc, buffer[i]);
	}

	return crc;
}

64-bit assembled output:

shr edx, 3
xor eax, eax
test edx, edx
je <label1>
nop dword ptr ds:[rax]

label2:
	mov eax, eax
	lea rcx, qword ptr ds:[rcx+8]
	crc32 rax, qword ptr ds:[rcx-8]
	dec rdx
	jne <label2>

label1:
	<end of 64-bit code>
*/
static uint64_t jmpAddr = 0;

uint32_t sse42_crc32_64bit(const uint32_t* buffer, const uint32_t _length)
{
	// Switch over to 64-bit mode to perform the CRC32 calculation.
	__asm
	{
		// x64 uses registers for first few arguments
		mov ecx, buffer
		mov edx, _length

		// jump to x64 mode
		lea ebx, jmpAddr // had trouble moving jmpAddr into eax once in 64-bit so just keep the jmpAddr in EBX

		mov dword ptr[ebx], offset _X64_MODE
		mov dword ptr[ebx + 4], 0x33
		jmp fword ptr[ebx]

	_X64_MODE:
		// 64-bit code as described in the function description.
		EM(0xC1) EM(0xEA) EM(0x03)
		EM(0x33) EM(0xC0)
		EM(0x85) EM(0xD2)
		EM(0x74) EM(0x19)

		EM(0x0F) EM(0x1F) EM(0x80) EM(0x00) EM(0x00) EM(0x00) EM(0x00)
		EM(0x8B) EM(0xC0)
		EM(0x48) EM(0x8D) EM(0x49) EM(0x08)
		EM(0xF2) EM(0x48) EM(0x0F) EM(0x38) EM(0xF1) EM(0x41) EM(0xF8)
		EM(0x48) EM(0xFF) EM(0xCA)
		EM(0x75) EM(0xEE)

		// jump back to x86 mode
		mov dword ptr[ebx], offset _X86_MODE
		mov dword ptr[ebx + 4], 0x23
		jmp fword ptr[ebx]
	}

_X86_MODE:
	uint32_t result;
	__asm mov result, eax
	return result;
}

/* Interface functions */

inline uint32_t crc32(const unsigned char* buffer, const uint32_t length)
{
	return sse42_crc32_32bit((uint32_t*)buffer, length);
	//return sse42_crc32_64bit((uint32_t*)buffer, length);
}

NOINLINE uint32_t checksum(const unsigned char* buffer, const uint32_t length)
{
	// TODO crc32 x64 has a theoretical throughput of 20.5GB/s (https://github.com/Cyan4973/xxHash/issues/62). Beats xxHash x64, but depends on having an Intel CPU.
	//return crc32(buffer, length);
	return XXH32(buffer, length, 0);
}