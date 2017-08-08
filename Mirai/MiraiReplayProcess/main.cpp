#include "thread.h"

int main(int argc, char** argv)
{
	// Loops infinitely without any address space interaction.
	// <jmp short eip-2>
	//__asm __emit 0xEB
	//__asm __emit 0xFE

	Util::Thread(GetCurrentThreadId(), GetCurrentProcessId()).Suspend();
}