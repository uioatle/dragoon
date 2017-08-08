#ifndef MIRAI_COMM_AREA_H
#define MIRAI_COMM_AREA_H

#include <Windows.h>

struct CommArea
{
	static const DWORD Size = 0x1000;

	enum Commands
	{
		WAIT_FOR_COMMAND,
		EXECUTE_BLOCK,
		EXECUTE_BLOCK_RESPONSE,
		NUM_COMMANDS
	};

	void* View;

	DWORD CommArea::GetCommand();
	void SetCommand(const DWORD command);

	CONTEXT& ExecuteBlock();
	void ExecuteBlock(const CONTEXT& ctx);

	CONTEXT& ExecuteBlockResponse();
	void ExecuteBlockResponse(const CONTEXT& ctx);
private:
	void* GetContentAddr();
};

#endif