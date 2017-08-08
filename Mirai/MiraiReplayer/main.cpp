#include "common.h"
#include "thread.h"
#include "module.h"
#include "smart_handle.h"
#include "memory_region.h"
#include "direct_address_space_recreation.h"
#include "shared.h"
#include "comm_area.h"

#include "distorm.h"
#include "mnemonics.h"

#include "asmjit.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <exception>
#include <functional>

using namespace asmjit;

void startComm(const Util::ThreadId waitingThreadId, const Util::ProcessId replayProcessId, Util::Module& replayerDll)
{
	// We can't start a remote thread before clearing the address space and have it wait for a volatile flag,
	// because that'll create a TEB and all that, messing up the recreation step.
	// Since we already have a thread at the waiting area (which was made for this exact purpose),
	// we can use that by redirecting its execution.
	Util::Thread waitingThread(waitingThreadId, replayProcessId);
	waitingThread.ChangeEip(replayerDll.GetExportedFunctionByName("startComm").addr);
	waitingThread.ForceResume();
}

CONTEXT loadRecordedThreadContext()
{
	// Retrieve recorded thread file name.
	const auto fileNames = Util::GetFileNamesInDirectory(recordingDir);
	std::vector<std::wstring> fileNamesWithCtxExtension;

	for (const auto& fileName : fileNames)
	{
		if (hasSuffix(fileName, L".ctx"))
		{
			fileNamesWithCtxExtension.push_back(fileName);
		}
	}

	// FOR DEBUGGING ONLY
	util_assert(fileNamesWithCtxExtension.size() == 1);

	// ASSUMES FIRST FILE IS CORRECT ONE - FOR DEBUGGING PURPOSES ONLY!
	// Retrieve recorded thread file.
	std::ifstream contextFile(recordingDir + fileNamesWithCtxExtension[0]);
	util_assert(contextFile);
	
	// Read the recorded thread context from the file.
	CONTEXT context;
	contextFile.read(reinterpret_cast<char*>(&context), sizeof(context));
	return context;
}

typedef struct
{
	_DInst inst;
	std::vector<unsigned char> rawBytes;
} Inst;

typedef struct
{
	std::vector<Inst> insts;
	std::function<_DecodedInst(_DInst)> DecodeInst;
} DecomposeInstructionsResults;

// Note:
// If not enough bytes were used to disassemble the instruction you'll end up
// with incorrect/invalid instructions at the end that seem correct but aren't.
// Disassembling must be done carefully!
DecomposeInstructionsResults decomposeInstructions(const DWORD codeOffset, const std::vector<unsigned char>& instBytes, const DWORD decomposerFeaturesFlags = DF_NONE);
DecomposeInstructionsResults decomposeInstructions(const DWORD codeOffset, const std::vector<unsigned char>& instBytes, const DWORD decomposerFeaturesFlags)
{
	// Decompose instructions.
	util_assert((instBytes.size() * 4) >= 2048);
	_DInst decodedInsts[2048];
	uint32_t decodedInstsCount = 0;

	_CodeInfo codeInfo;
	codeInfo.code = instBytes.data();
	codeInfo.codeLen = instBytes.size();
	codeInfo.codeOffset = codeOffset;
	codeInfo.dt = Decode32Bits;
	codeInfo.features = decomposerFeaturesFlags;

	const _DecodeResult decodeResult = distorm_decompose(&codeInfo, decodedInsts, sizeof(decodedInsts), &decodedInstsCount);
	if (decodeResult != DECRES_SUCCESS)
	{
		std::stringstream errorMsg;
		errorMsg << "distorm_decompose failed with error (_DecodeResult) " << decodeResult;
		throw std::exception(errorMsg.str().c_str());
	}

	/* Gather the results */
	DecomposeInstructionsResults results;

	results.DecodeInst = [&codeInfo](const _DInst& inst)
	{
		_DecodedInst decodedInst;
		distorm_format(&codeInfo, &inst, &decodedInst);
		return decodedInst;
	};

	// Build a list of the decomposed instructions and their raw bytes for convenient later use.
	const unsigned char* pCurrentInstByte = instBytes.data();
	for (uint32_t i = 0; i < decodedInstsCount; i++)
	{
		Inst inst;
		inst.inst = decodedInsts[i];

		for (uint32_t k = 0; k < inst.inst.size; k++)
			inst.rawBytes.push_back(*pCurrentInstByte++);

		results.insts.push_back(inst);
	}

	return results;
}

DecomposeInstructionsResults getInstsUntilFlowControl(const DWORD codeOffset, const std::vector<unsigned char>& instBytes)
{
	return decomposeInstructions(codeOffset, instBytes, DF_STOP_ON_FLOW_CONTROL);
}

std::vector<unsigned char> assemble(const std::function<void(X86Assembler&)>& f)
{
	JitRuntime rt;
	CodeHolder code;
	code.init(rt.getCodeInfo());
	X86Assembler a(&code);

	f(a);

	std::vector<unsigned char> assembledBytes;
	const unsigned char* bytePtr = a.getBufferData();
	for (uint32_t i = 0; i < code.getCodeSize(); i++)
	{
		assembledBytes.push_back(*bytePtr++);
	}
	return assembledBytes;
}

void addJmpToBlockFinishedExecuting(Util::Module& replayerDll, Util::MemoryRegion& codeBlockRegion, std::vector<unsigned char>& jitBuffer)
{
	const DWORD blockReturnAddr = (DWORD)replayerDll.GetExportedFunctionByName("blockFinishedExecuting").addr;
	const DWORD currentEip = (DWORD)codeBlockRegion.GetBaseAddress() + jitBuffer.size() - 1;
	const DWORD dstAddr = blockReturnAddr;
	const DWORD srcAddr = currentEip + 5;
	const DWORD jmpBytes = dstAddr - srcAddr;
	jitBuffer.push_back(0xE9); // JMP
	jitBuffer.push_back(jmpBytes & 0xFF);
	jitBuffer.push_back((jmpBytes >> 8) & 0xFF);
	jitBuffer.push_back((jmpBytes >> 16) & 0xFF);
	jitBuffer.push_back((jmpBytes >> 24) & 0xFF);
}

void writeJitBufferToCodeBlockRegion(Util::MemoryRegion& codeBlockRegion, const std::vector<unsigned char>& jitBuffer)
{
	codeBlockRegion.WriteData(jitBuffer.data(), jitBuffer.size(), false);
	codeBlockRegion.ChangeProtection(PAGE_EXECUTE_READ);
}

std::vector<unsigned char> readInstBytesFromReplayProcess(const Util::SmartHandle& hReplayProcess, void* eip)
{
	// Read instruction bytes at EIP from replay process.
	// TODO Might be able to replace this with shared memory for better performance.
	// TODO Have to give enough bytes so the last instruction(s) get disassembled correctly,
	// otherwise the disassembler will think it's another instruction if one or more bytes are missing, obviously.
	unsigned char _instBytes[512];
	Util::MemoryRegion(hReplayProcess, eip, sizeof(_instBytes)).ReadData(&_instBytes, sizeof(_instBytes));
	std::vector<unsigned char> instBytes;
	for (uint32_t i = 0; i < sizeof(_instBytes); i++) instBytes.push_back(_instBytes[i]);
	return instBytes;
}

void disasmAndPrintJitBuffer(const std::vector<unsigned char>& jitBuffer, const DWORD codeOffset)
{
	const auto jitBufferDisasm = decomposeInstructions(codeOffset, jitBuffer);
	for (const auto& inst : jitBufferDisasm.insts)
	{
		const _DecodedInst decodedInst = jitBufferDisasm.DecodeInst(inst.inst);
		printf("0x%08X: %s %s\n", (uint32_t)decodedInst.offset, decodedInst.mnemonic.p, decodedInst.operands.p);
	}
}

void assembleIntoBuffer(const std::function<void(X86Assembler&)>& f, std::vector<unsigned char>& buffer)
{
	const auto assembledBytes = assemble(f);
	buffer.insert(buffer.end(), assembledBytes.begin(), assembledBytes.end());
}

void handleFlowControlUnconditionalBranch(
	std::vector<unsigned char>& jitBuffer,
	const Inst fcInst,
	const DWORD nextBlockAddr,
	const std::function<void(std::vector<unsigned char>&)> fAddJmpToBlockFinishedExecuting
)
{
	// jmp rel8/16/32
	// Ex: jmp 0x12345
	if (fcInst.inst.ops[0].type == O_PC)
	{
		assembleIntoBuffer([&nextBlockAddr, &fcInst](X86Assembler& a) {
			a.mov(x86::dword_ptr(nextBlockAddr), Imm(INSTRUCTION_GET_TARGET(&fcInst.inst)));
		}, jitBuffer);
		fAddJmpToBlockFinishedExecuting(jitBuffer);
	}
	// jmp r/m16/32
	// Ex: jmp [0x12345]
	else if (fcInst.inst.ops[0].type == O_DISP)
	{
		assembleIntoBuffer([&nextBlockAddr, &fcInst](X86Assembler& a) {
			a.push(x86::eax);

			a.mov(x86::eax, x86::dword_ptr(fcInst.inst.disp));
			a.mov(x86::dword_ptr(nextBlockAddr), x86::eax);

			a.pop(x86::eax);
		}, jitBuffer);
		fAddJmpToBlockFinishedExecuting(jitBuffer);
	}
	else
	{
		throw std::invalid_argument("Branch instruction type not supported");
	}
}

void handleFlowControlCall(
	std::vector<unsigned char>& jitBuffer,
	const Inst fcInst,
	const DWORD nextBlockAddr,
	const std::function<void(std::vector<unsigned char>&)> fAddJmpToBlockFinishedExecuting
)
{
	assembleIntoBuffer([&fcInst](X86Assembler& a) { a.push(fcInst.inst.addr + fcInst.inst.size); }, jitBuffer);

	// call rel16/32
	// Ex: call 0x12345
	if (fcInst.inst.ops[0].type == O_PC)
	{
		assembleIntoBuffer([&nextBlockAddr, &fcInst](X86Assembler& a) {
			//a.push(fcInst.inst.addr + fcInst.inst.size);
			a.mov(x86::dword_ptr(nextBlockAddr), Imm(INSTRUCTION_GET_TARGET(&fcInst.inst)));
		}, jitBuffer);
		fAddJmpToBlockFinishedExecuting(jitBuffer);
	}
	// call r/m16/32
	// Ex: call [0x12345]
	else if (fcInst.inst.ops[0].type == O_DISP)
	{
		assembleIntoBuffer([&nextBlockAddr, &fcInst](X86Assembler& a) {
			a.push(x86::eax);

			a.mov(x86::eax, x86::dword_ptr(fcInst.inst.disp));
			a.mov(x86::dword_ptr(nextBlockAddr), x86::eax);

			a.pop(x86::eax);
		}, jitBuffer);
		fAddJmpToBlockFinishedExecuting(jitBuffer);
	}
	else
	{
		throw std::invalid_argument("CALL instruction type not supported");
	}
}

void handleFlowControlRet(
	std::vector<unsigned char>& jitBuffer,
	const Inst fcInst,
	const DWORD nextBlockAddr,
	const std::function<void(std::vector<unsigned char>&)> fAddJmpToBlockFinishedExecuting
)
{
	// ret
	// Ex: ret <nothing>
	if (fcInst.inst.ops[0].size == 0) // imm size == 0
	{
		assembleIntoBuffer([&nextBlockAddr](X86Assembler& a) { a.pop(x86::dword_ptr(nextBlockAddr)); }, jitBuffer);
		fAddJmpToBlockFinishedExecuting(jitBuffer);
	}
	else
	{
		throw std::invalid_argument("RET instruction type not supported");
	}
}

void handleFlowControlInst(
	std::vector<unsigned char>& jitBuffer,
	const Inst fcInst,
	DWORD nextBlockAddr,
	const std::function<void(std::vector<unsigned char>&)> fAddJmpToBlockFinishedExecuting
)
{
	switch (META_GET_FC(fcInst.inst.meta))
	{
	case FC_UNC_BRANCH:
		handleFlowControlUnconditionalBranch(jitBuffer, fcInst, nextBlockAddr, fAddJmpToBlockFinishedExecuting);
		break;
	case FC_CALL:
		handleFlowControlCall(jitBuffer, fcInst, nextBlockAddr, fAddJmpToBlockFinishedExecuting);
		break;
	case FC_RET:
		handleFlowControlRet(jitBuffer, fcInst, nextBlockAddr, fAddJmpToBlockFinishedExecuting);
		break;
	default:
		throw std::invalid_argument("fcInst is not a flow control instruction");
	}
}

void startReplay(const Util::SmartHandle& hReplayProcess, Util::Module& replayerDll, CommArea& commArea, void* nextBlockAddr, const CONTEXT& initialThreadContext)
{
	// Allocate space for the code block.
	Util::MemoryRegion codeBlockRegion(hReplayProcess, NULL, 0x1000);
	codeBlockRegion.Allocate(MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	const auto fAddJmpToBlockFinishedExecuting = [&replayerDll, &codeBlockRegion](std::vector<unsigned char>& jitBuffer)
	{
		addJmpToBlockFinishedExecuting(replayerDll, codeBlockRegion, jitBuffer);
	};

	auto ctx = initialThreadContext;

	while (true)
	{
		printf("EDI=%08X, ESI=%08X, EBX=%08X, EDX=%08X, ECX=%08X, EAX=%08X, EBP=%08X, ESP=%08X, EIP=%08X\n",
			ctx.Edi, ctx.Esi, ctx.Ebx, ctx.Edx, ctx.Ecx, ctx.Eax, ctx.Ebp, ctx.Esp, ctx.Eip);

		const auto instBytes = readInstBytesFromReplayProcess(hReplayProcess, (void*)ctx.Eip);

		// Build code block.
		std::vector<unsigned char> jitBuffer;

		const auto disasmResults = getInstsUntilFlowControl(ctx.Eip, instBytes);
		util_assert(!disasmResults.insts.empty());

		printf("\nDisasm:\n");

		// Add all instructions to the instruction stream except for the last flow control instruction.
		for (uint32_t i = 0; i < disasmResults.insts.size() - 1; i++)
		{
			const Inst inst = disasmResults.insts[i]; // TODO Should be reference?
			jitBuffer.insert(jitBuffer.end(), inst.rawBytes.begin(), inst.rawBytes.end());

			const auto di = disasmResults.DecodeInst(inst.inst);
			printf("%08X: %s %s\n", (uint32_t)di.offset, di.mnemonic.p, di.operands.p);
		}

		const auto fcInst = disasmResults.insts.back();
		const auto di = disasmResults.DecodeInst(fcInst.inst);
		printf("%08X: %s %s\n", (uint32_t)di.offset, di.mnemonic.p, di.operands.p);

		handleFlowControlInst(jitBuffer, fcInst, (DWORD)nextBlockAddr, fAddJmpToBlockFinishedExecuting);

		printf("\nJIT disasm:\n");
		disasmAndPrintJitBuffer(jitBuffer, (DWORD)codeBlockRegion.GetBaseAddress());
		writeJitBufferToCodeBlockRegion(codeBlockRegion, jitBuffer);

		// Command replay process to run code block.
		// EIP of the given context (struct) will be the starting point (altough not original EIP, but EIP of code block).
		ctx.Eip = (DWORD)codeBlockRegion.GetBaseAddress();
		commArea.ExecuteBlock(ctx);
		
		printf("-----------------------------------------------\n");
		getchar();

		do
		{
			Sleep(0);
		} while (commArea.GetCommand() != CommArea::Commands::EXECUTE_BLOCK_RESPONSE);

		ctx = commArea.ExecuteBlockResponse();
	}
}

void restoreOrgSyscallInterfaceInReplayProcess(const Util::SmartHandle& hReplayProcess)
{
	void* syscallInterfaceAddr = (void*)__readfsdword(0xC0);
	unsigned char syscallInterfaceBytes[7];

	Util::MemoryRegion(Util::SmartHandle(GetCurrentProcess(), NULL), syscallInterfaceAddr, sizeof(syscallInterfaceBytes))
		.ReadData(&syscallInterfaceBytes, sizeof(syscallInterfaceBytes));

	Util::MemoryRegion(hReplayProcess, syscallInterfaceAddr, sizeof(syscallInterfaceBytes))
		.WriteData(&syscallInterfaceBytes, sizeof(syscallInterfaceBytes));
}

int main(int argc, char** argv)
{
	try
	{
		/* Set up comm area */
		const Util::SmartHandle hCommAreaMapping(CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, CommArea::Size, L"CommAreaMapping"), NULL);
		auto commAreaView = MapViewOfFile(hCommAreaMapping.GetValue(), FILE_MAP_ALL_ACCESS, 0, 0, CommArea::Size);
		util_assert(commAreaView);
		CommArea commArea;
		commArea.View = commAreaView;

		/* Recreate recorded address space */
		const auto recordedMemRegionsFromDisk = loadRecordedMemoryRegionsFromDisk();
		const auto result = directlyRecreateAddressSpace(recordedMemRegionsFromDisk);
		// Using the WinAPI in the replay process is forbidden beyond this point.

		/* Set up some "globals" */
		const Util::SmartHandle hReplayProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, result.replayProcessId), NULL);
		Util::Module replayerDll(hReplayProcess, result.replayerDllBaseAddr);

		/* Restore syscall interface in replay process to its original form */
		// The recorded syscall interface was hooked. Since the hook target function doesn't exist (DragoonDll wasn't dumped) we'll
		// get errors if we try to jump to it. Therefore we restore the original syscall interface bytes.
		// TODO: We'll hook this later instead for the replay so we can install a replay syscall handler,
		// this is just temporary so things don't crash. Need to be able to disable the hook so
		// NtDelayExecution etc. in the replay process gets through.
		restoreOrgSyscallInterfaceInReplayProcess(hReplayProcess);

		/* Start communication */
		commArea.SetCommand(CommArea::Commands::WAIT_FOR_COMMAND);
		startComm(result.waitingThreadId, result.replayProcessId, replayerDll);

		/* Start replaying */
		startReplay(hReplayProcess, replayerDll, commArea, result.nextBlockAddr, loadRecordedThreadContext());
	}
	catch (const std::exception& e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}