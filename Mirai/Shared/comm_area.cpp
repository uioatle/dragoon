#include "comm_area.h"

void* CommArea::GetContentAddr()
{
	return (DWORD*)View + 1;
}

DWORD CommArea::GetCommand()
{
	return *(DWORD*)View;
}

void CommArea::SetCommand(const DWORD command)
{
	*(DWORD*)View = command;
}

CONTEXT& CommArea::ExecuteBlock()
{
	return *(CONTEXT*)GetContentAddr();
}

void CommArea::ExecuteBlock(const CONTEXT& ctx)
{
	*(CONTEXT*)GetContentAddr() = ctx;
	SetCommand(CommArea::Commands::EXECUTE_BLOCK);
}

CONTEXT& CommArea::ExecuteBlockResponse()
{
	return *(CONTEXT*)GetContentAddr();
}

void CommArea::ExecuteBlockResponse(const CONTEXT& ctx)
{
	*(CONTEXT*)GetContentAddr() = ctx;
	SetCommand(CommArea::Commands::EXECUTE_BLOCK_RESPONSE);
}