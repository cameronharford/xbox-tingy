#ifndef _TOOLS_H
#define _TOOLS_H

#pragma once
#include "stdafx.h"
#include "kernel.h"
#include <stdio.h>
#include <time.h>
#include <xtl.h>

extern BYTE CPUKey[0x10];
extern BYTE ModuleDigest[0x14];
extern BOOL Enabled;
extern DWORD NotifyType;

static MESSAGEBOX_RESULT Result;
static XOVERLAPPED Overlapped;
static LPCWSTR Buttons[] = { L"Default Open: Dpad Left + X", L"Open: RB + X", L"Open: Dpad Right + X" };
static PWCHAR Message = L"Refer to the Legacy Facebook page or Skype group for the update changelog\n\nMade by Soviet\nSkype: cycoticmongoose"; //Popup Message

class Tools {
public:
	static BOOL TrayOpen();
	static VOID XNotify(PWCHAR String, DWORD Type);
	static BOOL FileExists(CONST PCHAR FilePath);
	static BOOL CReadFile(CONST PCHAR FilePath, MemoryBuffer &Buffer);
	static BOOL CWriteFile(CONST PCHAR FilePath, CONST PVOID Buffer, DWORD Length);
	static BOOL InitializeHvxPeekPoke();
	static BYTE HvxPeekBYTE(QWORD Address);
	static WORD HvxPeekWORD(QWORD Address);
	static DWORD HvxPeekDWORD(QWORD Address);
	static QWORD HvxPeekQWORD(QWORD Address);
	static DWORD HvxPeekBytes(QWORD Address, PVOID Buffer, DWORD Length);
	static DWORD HvxPokeBYTE(QWORD Address, BYTE Value);
	static DWORD HvxPokeWORD(QWORD Address, WORD Value);
	static DWORD HvxPokeDWORD(QWORD Address, DWORD Value);
	static DWORD HvxPokeQWORD(QWORD Address, QWORD Value);
	static DWORD HvxPokeBytes(QWORD Address, CONST PVOID Buffer, DWORD Length);
	static QWORD HvxGetFuseLine(DWORD Index);
	static DWORD ResolveFunction(PCHAR ModuleName, DWORD Ordinal);
	static VOID PatchInJump(PDWORD Address, DWORD Destination);
	static DWORD RelinkGPLR(DWORD Offset, PDWORD SaveStub, PDWORD Original);
	static VOID HookFunctionStart(PDWORD Address, PDWORD SaveStub, DWORD Destination);
	static DWORD getAddedValueDWORD(DWORD first, DWORD second, int type);
	static PBYTE GetCPUKey();
	static PBYTE GetModuleDigest();
	static VOID GetPatchSha(PVOID Buffer);
	static PBYTE GetFuseDigest();
	static void CryptPatchData(PBYTE pbInpOut, DWORD cbInpOut);
	static void CryptServerData(PBYTE inBuf, DWORD inLen);
	static void mapHardDrive(int recursionCount);
	static DWORD getShaAddr();
	static DWORD getRc4Addr();
};
static DWORD resolveXamExport(DWORD Ordinal)
{
	char temp1[] = { ~'x', ~'a', ~'m', ~'.', ~'x', ~'e', ~'x', ~0 };
	char* temp2 = new char[sizeof(temp1)];
	for (int i = 0; i < sizeof(temp1); i++)
		temp2[i] = ~temp1[i];
	DWORD addr = Tools::ResolveFunction(temp2, Ordinal);
	delete[] temp2;
	return addr;
}
static DWORD resolveKrnlExport(DWORD Ordinal)
{
	char temp1[] = { ~'x', ~'b', ~'o', ~'x', ~'k', ~'r', ~'n', ~'l', ~'.', ~'e', ~'x', ~'e', ~0 };
	char* temp2 = new char[sizeof(temp1)];
	for (int i = 0; i < sizeof(temp1); i++)
		temp2[i] = ~temp1[i];
	DWORD addr = Tools::ResolveFunction(temp2, Ordinal);
	delete[] temp2;
	return addr;
}
static DWORD (_cdecl *XamGetCurrentTitleId)()
	= (DWORD(*)())resolveXamExport(0x1CF);//Tools::getAddedValueDWORD(0xF8E6314A, 0x79883142, 5);//0x816E0008;
	//= (DWORD(*)())Tools::ResolveFunction("xam.xex", 0x1CF);

static VOID (_cdecl *XNotifyQueueUI)(DWORD Type, DWORD UserIndex, QWORD Areas, PWCHAR String, PVOID Context)
	= (VOID(*)(DWORD, DWORD, QWORD, PWCHAR, PVOID))resolveXamExport(0x290);
	//= (VOID(*)(DWORD, DWORD, QWORD, PWCHAR, PVOID))Tools::ResolveFunction("xam.xex", 0x290);

static VOID (_cdecl *XNotifyUISetOptions)(BOOL Show, BOOL ShowMovie, BOOL PlaySound, BOOL ShowIPTV)
	= (VOID(*)(BOOL, BOOL, BOOL, BOOL))resolveXamExport(0x292);
	//= (VOID(*)(BOOL, BOOL, BOOL, BOOL))Tools::ResolveFunction("xam.xex", 0x292);

typedef VOID(*CryptRC4)(const PBYTE pbKey, DWORD cbKey, PBYTE pbInpOut, DWORD cbInpOut);

static PXBOX_KRNL_VERSION krnlVersion = (PXBOX_KRNL_VERSION)resolveKrnlExport(344);

#endif