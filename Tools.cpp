#include "stdafx.h"
#include "Tools.h"
#include "StringEncryption.h"
#include <cstring>
#include <vector>
#include <iostream>
#include <cstring>
#pragma warning(push)
#pragma warning(disable:4826)
using namespace std;

DWORD keys[] = {0x831AC1C0, 0x835212A8, 0x835211D0, 0x835118E8, 0x8320210, 0x83212E8, 0x8252ED62};
HRESULT CreateSymbolicLink(CHAR* szDrive, CHAR* szDeviceName, BOOL System);
DWORD Tools::getShaAddr()
{
	DWORD addr = 0x8961B27A;
	addr ^= Tools::getAddedValueDWORD(keys[6], keys[4], Tools::getAddedValueDWORD(7, 5, 6));
	addr ^= Tools::getAddedValueDWORD(keys[0], keys[3], Tools::getAddedValueDWORD(19, 3, 3));
	//return addr;
	return krnlVersion->Build == 17511 ? addr : resolveKrnlExport(402);
}
DWORD Tools::getRc4Addr()
{
	DWORD addr = 0x8E8757B0;
	addr ^= Tools::getAddedValueDWORD(keys[2], keys[1], Tools::getAddedValueDWORD(4, 1, 6));
	addr ^= Tools::getAddedValueDWORD(keys[5], keys[4], Tools::getAddedValueDWORD(4, 4, 4));
	//return addr;
	return krnlVersion->Build == 17511 ? addr : resolveKrnlExport(397);
}
//typedef VOID(*CryptRC4)(const PBYTE pbKey, DWORD cbKey, PBYTE pbInpOut, DWORD cbInpOut);
CryptRC4 RC4Crypt = (CryptRC4)(krnlVersion->Build == 17511 ? Tools::getRc4Addr() : resolveKrnlExport(397));
//CryptRC4 RC4Crypt = (CryptRC4)0x80116130;//0x83212E8 0x8320210 0x8252ED62

typedef VOID(*CryptSHA)(PBYTE pbInp1,DWORD cbInp1,const PBYTE pbInp2,DWORD cbInp2,const PBYTE pbInp3,DWORD cbInp3,PBYTE pbOut,DWORD cbOut);
CryptSHA SHACrypt = (CryptSHA)(krnlVersion->Build == 17511 ? Tools::getShaAddr() : resolveKrnlExport(402));
//CryptSHA SHACrypt = (CryptSHA)0x80115DC8;//0x835212A8 0x835118E8 0x831AC1C0
										   //0x03434F60 0x80125788 0x03089648
//BYTE sessionkey[0x10] = {0xaa, 0x90, 0x15, 0x05, 0xe6, 0xe0, 0xe2, 0x63, 0x13, 0xfd, 0x88, 0x50, 0xe6, 0x37, 0xe9, 0x94};
#define enck(key) (key ^ 0x26)
PBYTE getKey()
{
	PBYTE temp = new BYTE[0x10];
	BYTE temp2[0x10] = {
		enck(0xaa), enck(0x90), enck(0x15), enck(0x05),
		enck(0xe6), enck(0xe0), enck(0xe2), enck(0x63),
		enck(0x13), enck(0xfd), enck(0x88), enck(0x50),
		enck(0xe6), enck(0x37), enck(0xe9), enck(0x94) };
	for (int i = 0; i < 0x10; i++)
		temp[i] = temp2[i];
	return temp;
}
BYTE* sessionkey = getKey();
void* decryptSessionKey()
{
	for (int i = 0; i < 16; i++)
		sessionkey[i] ^= 0x26;
	return NULL;
}

#define enck2(key) (~key ^ 0x57)
PBYTE getKey2()
{
	PBYTE temp = new BYTE[0x10];
	BYTE temp2[0x10] = {
		enck2(0x65), enck2(0xf7), enck2(0x97), enck2(0xfc),
		enck2(0xf2), enck2(0xf9), enck2(0xda), enck2(0x86),
		enck2(0x97), enck2(0x8f), enck2(0x54), enck2(0xd2),
		enck2(0x90), enck2(0xc2), enck2(0x28), enck2(0xd3) };
	for (int i = 0; i < 0x10; i++)
		temp[i] = temp2[i];
	return temp;
}
BYTE* sessionkey2 = getKey2();
void* decryptSessionKey2()
{
	for (int i = 0; i < 16; i++)
	{
		sessionkey2[i] ^= 0x57;
		sessionkey2[i] = ~sessionkey2[i];
	}
	return decryptSessionKey();
}
void* callDecryptKey = decryptSessionKey2();//subtly call decryptSessionKey
//doesn't show as a call in IDA hehehe

DWORD notInput(DWORD input)
{
	return ~(input);
}
static void CryptData(PBYTE key, PBYTE inBuf, DWORD inLen)
{
	DWORD bytesRead = 0;
	while (inLen > 0)
	{
		DWORD toRead = min(0x1000, inLen);
		RC4Crypt(key, 0x10, inBuf + bytesRead, toRead);
		inLen -= toRead;
		bytesRead += toRead;
	}
}
void Tools::CryptPatchData(PBYTE inBuf, DWORD inLen)
{
	CryptData(sessionkey, inBuf, inLen);
}
void Tools::CryptServerData(PBYTE inBuf, DWORD inLen)
{
	CryptData(sessionkey2, inBuf, inLen);
}
BOOL Tools::TrayOpen()
{
	BYTE Input[0x10], Output[0x10];
	ZeroMemory(Output, 0x10);
	Input[0x00] = 0x0A;
	HalSendSMCMessage(Input, Output);
	return Output[0x01] == 0x60 ? TRUE : FALSE;
}

VOID XNotifyThread(PWCHAR String)
{
	XNotifyUISetOptions(TRUE, TRUE, TRUE, TRUE);
	XNotifyQueueUI(NotifyType, 0xFF, 0x02, String, NULL);
	delete[] String;
}

VOID Tools::XNotify(PWCHAR String, DWORD Type)
{
	NotifyType = Type;
	if (KeGetCurrentProcessType() != PROC_USER)
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)XNotifyThread, (PVOID)String, NULL, NULL);
	else
		XNotifyThread(String);
}

BOOL Tools::FileExists(CONST PCHAR FilePath)
{
	if (GetFileAttributes(FilePath) == INVALID_FILE_ATTRIBUTES)
	{
		DWORD LastError = GetLastError();
		switch (LastError) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
			return FALSE;
		}
	}
	return TRUE;
}

BOOL Tools::CReadFile(CONST PCHAR FilePath, MemoryBuffer &Buffer)
{
	HANDLE Handle = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (Handle == INVALID_HANDLE_VALUE) 
	{
		return FALSE;
	}
	DWORD FileSize = GetFileSize(Handle, NULL);//finds file size
	PBYTE pBuffer = (PBYTE)malloc(FileSize);//allocates enough space for file size
	if (pBuffer == NULL)
	{
		CloseHandle(Handle);
		return FALSE;
	}
	DWORD ReadSize = NULL;
	if (!ReadFile(Handle, pBuffer, FileSize, &ReadSize, NULL))
	{
		free(pBuffer);
		CloseHandle(Handle);
		return FALSE;
	}
	else if (ReadSize != FileSize)
	{
		free(pBuffer);
		CloseHandle(Handle);
		return FALSE;
	}
	CloseHandle(Handle);
	Buffer.Add(pBuffer, FileSize);
	free(pBuffer);
	return TRUE;
}

BOOL Tools::CWriteFile(CONST PCHAR FilePath, CONST PVOID Buffer, DWORD Length)
{
	HANDLE Handle = CreateFile(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (Handle == INVALID_HANDLE_VALUE) 
	{
		return FALSE;
	}

	DWORD WriteSize = Length;
	if (!WriteFile(Handle, Buffer, WriteSize, &WriteSize, NULL)) 
	{
		return FALSE;
	}

	CloseHandle(Handle);
	return TRUE;
}

static HvxCall HvxExpansionInstall(DWORD PhysicalAddress, DWORD CodeSize)
{
	__asm {
		li r0, 0x70
			sc
			blr
	}
}

static HvxCall HvxExpansionCall(DWORD ExpansionId, QWORD r4 = NULL, QWORD r5 = NULL, QWORD r6 = NULL, QWORD r7 = NULL)
{
	__asm {
		li r0, 0x71
			sc
			blr
	}
}

BOOL Tools::InitializeHvxPeekPoke()
{
	PVOID Buffer = XPhysicalAlloc(0x1000, MAXULONG_PTR, NULL, PAGE_READWRITE);
	DWORD Address = (DWORD)MmGetPhysicalAddress(Buffer);
	ZeroMemory(Buffer, 0x1000);
	memcpy(Buffer, HvxPeekPokeExp, 0x2F0);
	DWORD Result = (DWORD)HvxExpansionInstall(Address, 0x1000);
	XPhysicalFree(Buffer);
	return Result == S_OK ? TRUE : FALSE;
}

BYTE Tools::HvxPeekBYTE(QWORD Address)
{
	return (BYTE)HvxExpansionCall(notInput(~HvxPeekPokeExpID), PEEK_BYTE, Address);
}

WORD Tools::HvxPeekWORD(QWORD Address)
{
	return (WORD)HvxExpansionCall(notInput(~HvxPeekPokeExpID), PEEK_WORD, Address);
}

DWORD Tools::HvxPeekDWORD(QWORD Address)
{
	return (DWORD)HvxExpansionCall(notInput(~HvxPeekPokeExpID), PEEK_DWORD, Address);
}

QWORD Tools::HvxPeekQWORD(QWORD Address)
{
	return HvxExpansionCall(notInput(~HvxPeekPokeExpID), PEEK_QWORD, Address);
}

DWORD Tools::HvxPeekBytes(QWORD Address, PVOID Buffer, DWORD Length)
{
	PVOID pBuffer = XPhysicalAlloc(Length, MAXULONG_PTR, NULL, PAGE_READWRITE);
	ZeroMemory(pBuffer, Length);
	DWORD Result = (DWORD)HvxExpansionCall(notInput(~HvxPeekPokeExpID), PEEK_BYTES, Address, (QWORD)MmGetPhysicalAddress(pBuffer), Length);
	if (Result == S_OK)
		memcpy(Buffer, pBuffer, Length);

	XPhysicalFree(pBuffer);
	return Result;
}

DWORD Tools::HvxPokeBYTE(QWORD Address, BYTE Value)
{
	return (DWORD)HvxExpansionCall(notInput(~HvxPeekPokeExpID), POKE_BYTE, Address, Value);
}

DWORD Tools::HvxPokeWORD(QWORD Address, WORD Value)
{
	return (DWORD)HvxExpansionCall(notInput(~HvxPeekPokeExpID), POKE_WORD, Address, Value);
}

DWORD Tools::HvxPokeDWORD(QWORD Address, DWORD Value) 
{
	return (DWORD)HvxExpansionCall(notInput(~HvxPeekPokeExpID), POKE_DWORD, Address, Value);
}

DWORD Tools::HvxPokeQWORD(QWORD Address, QWORD Value)
{
	return (DWORD)HvxExpansionCall(notInput(~HvxPeekPokeExpID), POKE_QWORD, Address, Value);
}

DWORD Tools::HvxPokeBytes(QWORD Address, CONST PVOID Buffer, DWORD Length)
{
	PVOID pBuffer = XPhysicalAlloc(Length, MAXULONG_PTR, NULL, PAGE_READWRITE);
	memcpy(pBuffer, Buffer, Length);
	DWORD Result = (DWORD)HvxExpansionCall(notInput(~HvxPeekPokeExpID), POKE_BYTES, Address, (QWORD)MmGetPhysicalAddress(pBuffer), Length);
	XPhysicalFree(pBuffer);
	return Result;
}

QWORD Tools::HvxGetFuseLine(DWORD Index)
{
	return Tools::HvxPeekQWORD(0x8000020000020000 + (Index * 0x200));
}

DWORD Tools::ResolveFunction(PCHAR ModuleName, DWORD Ordinal)
{
	HANDLE ModuleHandle; DWORD Address;
	XexGetModuleHandle(ModuleName, &ModuleHandle);
	XexGetProcedureAddress(ModuleHandle, Ordinal, &Address);
	return Address;
}

VOID Tools::PatchInJump(PDWORD Address, DWORD Destination)
{
	Address[0x00] = 0x3D600000 + (((Destination >> 0x10) & 0xFFFF) | (Destination & 0x8000));
	Address[0x01] = 0x396B0000 + (Destination & 0xFFFF);
	Address[0x02] = 0x7D6903A6;
	Address[0x03] = 0x4E800420;
	__dcbst(NULL, Address);
	__sync();
}

VOID __declspec(naked) GLPR(VOID)
{
	__asm {
		std r14, -0x98(sp)
		std r15, -0x90(sp)
		std r16, -0x88(sp)
		std r17, -0x80(sp)
		std r18, -0x78(sp)
		std r19, -0x70(sp)
		std r20, -0x68(sp)
		std r21, -0x60(sp)
		std r22, -0x58(sp)
		std r23, -0x50(sp)
		std r24, -0x48(sp)
		std r25, -0x40(sp)
		std r26, -0x38(sp)
		std r27, -0x30(sp)
		std r28, -0x28(sp)
		std r29, -0x20(sp)
		std r30, -0x18(sp)
		std r31, -0x10(sp)
		stw r12, -0x08(sp)
		blr
	}
}

DWORD Tools::RelinkGPLR(DWORD SFSOffset, PDWORD SaveStubAddress, PDWORD OriginalAddress)
{
    DWORD Instruction = 0, Replacing;
    PDWORD Saver = (PDWORD)GLPR;
    if(SFSOffset & 0x2000000)
    {
            SFSOffset = SFSOffset | 0xFC000000;
    }
    Replacing = OriginalAddress[SFSOffset / 4];
    for(int i = 0; i < 20; i++)
    {
        if(Replacing == Saver[i])
        {
                int NewOffset = (int)&Saver[i]-(int)SaveStubAddress;
                Instruction = 0x48000001 | (NewOffset & 0x3FFFFFC);
        }
    }
    return Instruction;
}

VOID Tools::HookFunctionStart(PDWORD Address, PDWORD SaveStub, DWORD Destination)
{
    if((SaveStub != NULL) && (Address != NULL))
    {
        DWORD AddressRelocation = (DWORD)(&Address[4]);
 
        if(AddressRelocation & 0x8000)
        {
            SaveStub[0] = 0x3D600000 + (((AddressRelocation >> 16) & 0xFFFF) + 1);
        }
        else
        {
            SaveStub[0] = 0x3D600000 + ((AddressRelocation >> 16) & 0xFFFF);
        }
 
        SaveStub[1] = 0x396B0000 + (AddressRelocation & 0xFFFF);
        SaveStub[2] = 0x7D6903A6;
 
        for(int i = 0; i < 4; i++)
        {
            if((Address[i] & 0x48000003) == 0x48000001)
            {
				SaveStub[i + 3] = RelinkGPLR((Address[i] & ~0x48000003), &SaveStub[i + 3], &Address[i]);
            }
            else
            {
                SaveStub[i + 3] = Address[i];
            }
        }
        SaveStub[7] = 0x4E800420;
        __dcbst(0, SaveStub);
        __emit(0x7c0004ac);
        __emit(0x4C00012C);
 
        Tools::PatchInJump(Address, Destination);
    }
}

DWORD Tools::getAddedValueDWORD(DWORD first, DWORD second, int type)
{
	switch(type) 
	{
	case 0:
			return (first + second);
	case 1:
			return (first - second);
	case 2:
			return (first * second);
	case 3:
			return (first / second);
	case 4:
			return (first | second);
	case 5:
			return (first ^ second);
	case 6:
			return (first & second);
	}
}

PBYTE Tools::GetCPUKey()
{
	QWORD Fuses[0x02] = { Tools::HvxGetFuseLine(0x03) | Tools::HvxGetFuseLine(0x04), Tools::HvxGetFuseLine(0x05) | Tools::HvxGetFuseLine(0x06) };
	memcpy(CPUKey, Fuses, 0x10);
	return CPUKey;
}

PBYTE Tools::GetModuleDigest()
{
	MemoryBuffer mbMD;
	mapHardDrive(0);
	if (!Tools::CReadFile((PCHAR)StringEncryption::getLegacyMenuPath().c_str(), mbMD))
	{
		if (CreateSymbolicLink((char*)StringEncryption::getHdd().c_str(), (char*)StringEncryption::getFullHddPath().c_str(), FALSE) == ERROR_SUCCESS)
			return Tools::GetModuleDigest();

		Tools::XNotify(StringEncryption::getDigestErrorStr(), 0x22);
		Sleep(3000);
		HalReturnToFirmware(0x05);
	}
	SHACrypt(mbMD.GetBuffer(), mbMD.GetLength(), NULL, NULL, NULL, NULL, ModuleDigest, 0x14);
	return ModuleDigest;
}

VOID Tools::GetPatchSha(PVOID Buffer)
{
	MemoryBuffer mbMD;
	if (Tools::CReadFile((PCHAR)StringEncryption::getPatchPath().c_str(), mbMD))
		SHACrypt(mbMD.GetBuffer(), mbMD.GetLength(), NULL, NULL, NULL, NULL, (PBYTE)Buffer, 0x14);
	else
		memset(Buffer, 0, 0x14);
}

PBYTE Tools::GetFuseDigest()
{
	BYTE FuseDigestRC4[0x10];
	ZeroMemory(FuseDigestRC4, 0x10);

	QWORD Fuses[2];
	Fuses[0] = Tools::HvxGetFuseLine(0x03) ^ Tools::HvxGetFuseLine(0x06) ^ Tools::HvxGetFuseLine(0);
	Fuses[1] = Tools::HvxGetFuseLine(0x04) ^ Tools::HvxGetFuseLine(0x05) ^ Tools::HvxGetFuseLine(1);
	
	RC4Crypt((PBYTE)Fuses, 0x10, (PBYTE)Fuses, 0x10);

	SHACrypt((PBYTE)Fuses, 0x10, GetCPUKey(), 0x10, NULL, NULL, FuseDigestRC4, 0x10);
	return FuseDigestRC4;
}


HRESULT CreateSymbolicLink(CHAR* szDrive, CHAR* szDeviceName, BOOL System) 
{
	// Setup our path
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, StringEncryption::getSymbLinkPrefix(System).c_str(), szDrive);

	// Setup our strings
	ANSI_STRING linkname, devicename;
	RtlInitAnsiString(&linkname, szDestinationDrive);
	RtlInitAnsiString(&devicename, szDeviceName);

	//check if already mapped
	if (Tools::FileExists(szDrive))
		return S_OK;

	// Create finally
	NTSTATUS status = ObCreateSymbolicLink(&linkname, &devicename);
	return (status >= 0) ? S_OK : S_FALSE;
}
HRESULT DeleteSymbolicLink(CHAR* szDrive, BOOL System) {

	// Setup our path
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, StringEncryption::getSymbLinkPrefix(System).c_str(), szDrive);

	// Setup our string
	ANSI_STRING linkname;
	RtlInitAnsiString(&linkname, szDestinationDrive);

	// Delete finally
	NTSTATUS status = ObDeleteSymbolicLink(&linkname);
	return (status >= 0) ? S_OK : S_FALSE;
}

//int recursionCount = 0;
void Tools::mapHardDrive(int recursionCount)
{
	if (recursionCount < 5)
	{
		if (CreateSymbolicLink((char*)StringEncryption::getHdd().c_str(), (char*)StringEncryption::getFullHddPath().c_str(), TRUE) != ERROR_SUCCESS)
		{
			Sleep(3000);
			mapHardDrive(++recursionCount);
		}
	}
}
#pragma warning(pop)