#include <cstdio>
#include <Windows.h>

void step4()
{
	__asm mov eax, 4
}

void step6(){
	__asm mov eax, 6
}

void step5()
{
	__asm mov eax, 5
	step6();
}

int step9(const int a, const int b)
{
	return a + b;
}

int main(int argc, char** argv)
{
	__asm
	{
		// Short positive jump.
		mov eax, 0
		jmp l1

	l2:
		mov eax, 2
		jmp l3
	
	l1:
		// Short negative jump.
		mov eax, 1
		jmp l2

	l3:
		mov eax, 3
	}

	step4();
	step5();

	__asm mov eax, 7

	const auto threadId = GetCurrentThreadId();

	__asm mov eax, 8

	const auto result = step9(4, 5);

	if (!VirtualAlloc((void*)0x50000000, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
	{
		__asm int 3;
		__asm int 1;
	}

	unsigned char buffer[1] = { 0x90 };
	void* addr = (char*)0x50000000 + 0x2000 + 0x10;
	if (!WriteProcessMemory(GetCurrentProcess(), addr, &buffer, sizeof(buffer), NULL))
	{
		__asm int 3;
		__asm int 1;
	}
}