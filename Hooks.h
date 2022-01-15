#pragma once
#include "stdafx.h"

class Hooks
{
public:
	static void loadKernelHooks();
	static void loadPatch();
	static void loadPatch(PBYTE Buffer, DWORD len);
	static bool replaceBuffer(PBYTE Buffer, DWORD Offset, DWORD Length);
};