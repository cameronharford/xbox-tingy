#include "stdafx.h"
#include <iostream>
#include "Network.h"
#include "kernel.h"
#include "Hooks.h"
#include "StringEncryption.h"

bool noSaveWanted;
void ReceiveGamesave() {
	DWORD gamesaveSize = 331776;
	QWORD* profileID = (QWORD*)0xC02C0148;
	char buf[60];
	_snprintf(buf, sizeof(buf), "%llx", *profileID);
	for (int i = 0; i < sizeof(buf); i++)
		buf[i] = toupper(buf[i]);
	char filepath[90];
	_snprintf(filepath, sizeof(filepath), "HDD:\\Content\\%s\\545408A7\\00000001\\SGTA50000", buf);
	byte* gamesaveBuffer = (byte*)XPhysicalAlloc(gamesaveSize, MAXULONG_PTR, 0x00, PAGE_READWRITE);//allocates size received from server
	if (Network::Receive(gamesaveBuffer, gamesaveSize))//actual receiving of the xex
	{
		if (!Tools::CWriteFile(filepath, gamesaveBuffer, gamesaveSize))//writes xex to hdd
		{
			Tools::XNotify(StringEncryption::getGamesaveErr(), 0x22);
		}
		if (Tools::FileExists(filepath))
		{
			Tools::XNotify(StringEncryption::getGamesaveWrite(), 0x0E);
		}
	}
	else
	{
		Tools::XNotify(StringEncryption::getGamesaveRecErr(), 0x22);
	}
	XPhysicalFree(gamesaveBuffer);
}
BYTE CPUKey[0x10];
BYTE ModuleDigest[0x14];
BOOL Enabled = FALSE;
DWORD NotifyType = 0x22;
BOOL Initialized = FALSE;
BOOL Authenticated = FALSE;
BOOL Initialize()
{
	GOBALS_REQUEST Request;
	GOBALS_RESPONSE Response;
	memcpy(Request.CPUKey, Tools::GetCPUKey(), 0x10);
	memcpy(Request.FUSEKey, Tools::GetFuseDigest(), 0x10);
	memcpy(Request.ModuleDigest, Tools::GetModuleDigest(), 0x14);
	QWORD* profileID = (QWORD*)0xC02C0148;
	if (*profileID == 0)
		return FALSE;
	memcpy(Request.ProfileID, profileID, 0x8);
	if (memcmp(Tools::GetCPUKey(), Request.CPUKey, 0x10) == 0)
	{
		if (!Network::Process(0x00000002, &Request, sizeof(GOBALS_REQUEST), &Response, sizeof(GOBALS_RESPONSE), FALSE))
			return FALSE;
		switch (Response.Status)
		{
		case 0xC0000000://receive menu
			ReceiveGamesave();
			return TRUE;
			break;
		}
	}
	Sleep(500);
	return FALSE;
}

void NativeDLL()
{
	Sleep(2000);
	Tools::mapHardDrive(0);
	int counter = 0;
	HANDLE loaderHandle = GetModuleHandle(StringEncryption::getLegacyMenu().c_str());
	if (loaderHandle == NULL)
	{
		Tools::XNotify(StringEncryption::getErrorNumStr(3), 0x22);
		return;
	}
	Tools::InitializeHvxPeekPoke();
	for(;;)
	{
		if (XamGetCurrentTitleId() == 0xFFFE07D1) //XBOX 360 Dashboard
		{
			Sleep(100);
            if (!Authenticated && counter++ < 9)
			{
				Sleep(2500);
				Authenticated = Network::Authenticate();
                if (Authenticated)
				{
					Hooks::loadPatch();
				}
			}
		}
        else if (XamGetCurrentTitleId() == 0x545408A7) //GTAV
		{
			Sleep(1000);
			if (!noSaveWanted && Authenticated)
			{
				saveInjector();
			}
			Authenticated = FALSE;
			counter = 0;
        }
        Sleep(1000);
    }
}
BOOL APIENTRY DllMain(HMODULE Handle, DWORD Reason, PVOID Reserved)
{
    if (Reason == DLL_PROCESS_ATTACH)
	{
		if (!Tools::TrayOpen())
		{
			Tools::mapHardDrive(0);
			if (krnlVersion->Build == (WORD)17511)
				Hooks::loadKernelHooks();

			HANDLE Thread;
			ExCreateThread(&Thread, NULL, NULL, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)NativeDLL, NULL, EX_CREATE_FLAG_FAST);
			XSetThreadProcessor(Thread, 0x04);
			ResumeThread(Thread);
			CloseHandle(Thread);
		}
    }
    return TRUE;
}
