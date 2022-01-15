#include "stdafx.h"
#include "Network.h"
#include "Hooks.h"
#include "StringEncryption.h"
#include <string>

static DWORD Return20()
{
	return 20;//JumpGetModuleSize()
}
static DWORD Return16()
{
	return 16;//0x10
}
static DWORD NotInput(DWORD input)
{
	return ~(input);
}
#pragma region Jump Table Stuff
typedef DWORD(__cdecl *JumpTableEnt)(...);
JumpTableEnt *ServerJumpTable = new JumpTableEnt[26];

#define JumpReceivePatch		ServerJumpTable[0]
#define JumpNetCloseSocket		ServerJumpTable[1]
#define JumpNetSocket			ServerJumpTable[3]
#define JumpMemcpy				ServerJumpTable[4]
#define JumpGetModuleDigest		ServerJumpTable[5]
#define JumpNetConnect			ServerJumpTable[6]
#define JumpReceiveUpdate		ServerJumpTable[7]
#define JumpDisconnect			ServerJumpTable[8]
#define JumpGetCpu				ServerJumpTable[9]
#define JumpProcess				ServerJumpTable[10]
#define JumpMemcmp				ServerJumpTable[11]
#define JumpNetXNetStartup		ServerJumpTable[12]
#define JumpGetFuseDigest		ServerJumpTable[13]
#define JumpEncryptedAlloc		ServerJumpTable[14]
#define JumpWriteFile			ServerJumpTable[15]
#define JumpNetSetSockOpt		ServerJumpTable[16]
#define JumpGetModuleSize		ServerJumpTable[17]
#define JumpNetRecv				ServerJumpTable[18]
#define JumpReceiveMenu			ServerJumpTable[19]
#define JumpXNotify				ServerJumpTable[20]
#define JumpGetCpuSize			ServerJumpTable[21]
#define JumpNetSend				ServerJumpTable[22]
#define JumpNetWSAStartupEx		ServerJumpTable[23]
#define JumpNotInput			ServerJumpTable[24]
#define JumpReboot				ServerJumpTable[25]
typedef void * (__cdecl *ThumpContinuation)(...);
void *SetupServerJumpTable()
{
	JumpReceivePatch = (JumpTableEnt)Network::ReceivePatch;
	JumpNetCloseSocket = (JumpTableEnt)NetDll_closesocket;
	JumpMemcpy = (JumpTableEnt)memcpy;
	JumpGetModuleDigest = (JumpTableEnt)Tools::GetModuleDigest;
	JumpNetConnect = (JumpTableEnt)NetDll_connect;
	JumpReceiveUpdate = (JumpTableEnt)Network::ReceiveUpdate;
	JumpDisconnect = (JumpTableEnt)Network::Disconnect;
	JumpGetCpu = (JumpTableEnt)Tools::GetCPUKey;
	JumpProcess = (JumpTableEnt)Network::Process;
	JumpMemcmp = (JumpTableEnt)memcmp;
	JumpGetFuseDigest = (JumpTableEnt)Tools::GetFuseDigest;
	JumpEncryptedAlloc = (JumpTableEnt)XEncryptedAlloc;
	JumpWriteFile = (JumpTableEnt)Tools::CWriteFile;
	JumpNetRecv = (JumpTableEnt)NetDll_recv;
	JumpReceiveMenu = (JumpTableEnt)Network::ReceiveMenu;
	JumpXNotify = (JumpTableEnt)Tools::XNotify;
	JumpNetSend = (JumpTableEnt)NetDll_send;

	JumpNetSetSockOpt = (JumpTableEnt)NetDll_setsockopt;
	JumpNetWSAStartupEx = (JumpTableEnt)NetDll_WSAStartupEx;
	JumpNetXNetStartup = (JumpTableEnt)NetDll_XNetStartup;
	JumpNetSocket = (JumpTableEnt)NetDll_socket;
	JumpGetModuleSize = (JumpTableEnt)Return20;
	JumpGetCpuSize = (JumpTableEnt)Return16;
	JumpNotInput = (JumpTableEnt)NotInput;
	JumpReboot = (JumpTableEnt)HalReturnToFirmware;
	return NULL;
}
void* garbagePtr = SetupServerJumpTable();
#pragma endregion

DWORD(*XexLoadImageFromMem)(
	PVOID pvXexBuffer,
	DWORD dwSize,
	LPCSTR szXexName,
	DWORD dwModuleTypeFlags,
	DWORD dwMinimumVersion, 
	PHANDLE pHandle) = (DWORD(*)(PVOID, DWORD, LPCSTR, DWORD, DWORD, PHANDLE))Tools::getAddedValueDWORD(0x80000000, Tools::getAddedValueDWORD(0xEEE91, 0x92149, 5), 4);
	//0x8007CFD8;//17511

SOCKET Network::Connect()
{
	XNetStartupParams XNSP;
	ZeroMemory(&XNSP, sizeof(XNSP));
	XNSP.cfgSizeOfStruct = sizeof(XNetStartupParams);
	XNSP.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;
	if (JumpNetXNetStartup(XNCALLER_SYSAPP, &XNSP) != S_OK)
		return INVALID_SOCKET;

	WSADATA WsaData;
	if (JumpNetWSAStartupEx(XNCALLER_SYSAPP, MAKEWORD(0x02, 0x02), &WsaData, 0x02) != S_OK)
		return INVALID_SOCKET;

	if ((m_Socket = JumpNetSocket(XNCALLER_SYSAPP, AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
		return INVALID_SOCKET;

	BOOL SockOpt = TRUE;
	if (JumpNetSetSockOpt(XNCALLER_SYSAPP, m_Socket, SOL_SOCKET, 0x5801, (CONST PCHAR)&SockOpt, 0x04) != S_OK)
		return INVALID_SOCKET;

	DWORD SendRecvSize = 0x800;
	JumpNetSetSockOpt(XNCALLER_SYSAPP, m_Socket, SOL_SOCKET, SO_SNDBUF, (CONST PCHAR)&SendRecvSize, 0x04);
	JumpNetSetSockOpt(XNCALLER_SYSAPP, m_Socket, SOL_SOCKET, SO_RCVBUF, (CONST PCHAR)&SendRecvSize, 0x04);

	sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(Port);    
	sockaddr.sin_addr.S_un.S_un_b.s_b1 = IP[0x00];
	sockaddr.sin_addr.S_un.S_un_b.s_b2 = IP[0x01];
	sockaddr.sin_addr.S_un.S_un_b.s_b3 = IP[0x02];
	sockaddr.sin_addr.S_un.S_un_b.s_b4 = IP[0x03];
	if (JumpNetConnect(XNCALLER_SYSAPP, m_Socket, (struct sockaddr*)&sockaddr, sizeof(sockaddr_in)) == SOCKET_ERROR)
		return INVALID_SOCKET;

	return m_Socket;
}

VOID Network::Disconnect()
{
	JumpNetCloseSocket(XNCALLER_SYSAPP, m_Socket);
	m_Socket = NULL;
}

BOOL Network::Send(DWORD Command, PVOID Buffer, DWORD Length)
{
	PBYTE Temp = new BYTE[Length + 0x08];
	JumpMemcpy(Temp, &Command, 0x04);
	JumpMemcpy(Temp + 0x04, &Length, 0x04);
	JumpMemcpy(Temp + 0x08, Buffer, Length);

	DWORD Remaining = Length + 0x08;
	Tools::CryptServerData(Temp, 0x08);
	Tools::CryptServerData(Temp + 8, Length);
	PCHAR Current = (PCHAR)Temp;
	while (Remaining > NULL)
	{
		DWORD SendSize = min(0x800, Remaining);
		DWORD Sent = JumpNetSend(XNCALLER_SYSAPP, m_Socket, Current, SendSize, NULL);
		if (Sent == SOCKET_ERROR)
		{
			delete[] Temp;
			return FALSE;
		}
		Remaining -= Sent;
		Current += Sent;
	}
	delete[] Temp;
	return TRUE;
}

BOOL Network::Receive(PVOID Buffer, DWORD Length)
{
	DWORD Remaining = Length;
	DWORD Received = NULL;
	while (Remaining > NULL)
	{
		DWORD RecvSize = min(0x800, Remaining);
		DWORD Recv = JumpNetRecv(XNCALLER_SYSAPP, m_Socket, (PCHAR)Buffer + Received, RecvSize, NULL);
		if (Recv == SOCKET_ERROR)
			return FALSE;

		if (Recv == NULL)
			break;

		Remaining -= Recv;
		Received += Recv;
	}
	if (Received != Length)
		return FALSE;

	Tools::CryptServerData((PBYTE)Buffer, Received);

	return TRUE;
}

BOOL Network::Process(DWORD Command, PVOID Request, DWORD RequestLength, PVOID Response, DWORD ResponseLength, BOOL Close)
{
	if (Network::Connect() == INVALID_SOCKET)
		return FALSE;
	if (!Network::Send(Command, Request, RequestLength))
		return FALSE;
	if (!Network::Receive(Response, ResponseLength))
		return FALSE;
	if (Close) 
		JumpDisconnect();
	return TRUE;
}

VOID Network::ReceiveUpdate()
{
	DWORD ModuleSize = NULL;
	if (!Network::Receive(&ModuleSize, 0x04)) 
	{
		//gets the xex size/length from server
		JumpXNotify(StringEncryption::getUpdError(), JumpNotInput(~0x22));
		Sleep(3000);
		JumpReboot(JumpNotInput(~0x05));
	}

	PBYTE ModuleBuffer = (PBYTE)XPhysicalAlloc(ModuleSize, MAXULONG_PTR, 0x00, PAGE_READWRITE);//allocates size received from server
	if (Network::Receive(ModuleBuffer, ModuleSize))//actual receiving of the xex
	{
		if (!JumpWriteFile((PCHAR)StringEncryption::getLegacyMenuPath().c_str(), ModuleBuffer, ModuleSize))//writes xex to hdd
		{
			JumpXNotify(StringEncryption::getUpdWriteError(), JumpNotInput(~0x22));
			Sleep(3000);
			JumpReboot(JumpNotInput(~0x05));
		}
	}
	XPhysicalFree(ModuleBuffer);//frees the allocated space for holding the xex
	JumpDisconnect();
	JumpXNotify(StringEncryption::getUpdCmpl(), JumpNotInput(~0x22));
	Sleep(5000);
	JumpReboot(JumpNotInput(~0x03));
}

std::string dankHax()
{
	std::string retVal;
	unsigned char kahoot[7] = { 0x08, 0x58, 0x10, 0x28, 0x28, 0xF0, 0x53 };
	for (unsigned int HtOgT = 0, mLVSB = 0; HtOgT < 7; HtOgT++)
	{
		mLVSB = kahoot[HtOgT];
		mLVSB = ~mLVSB;
		mLVSB ^= 0xAC;
		mLVSB = ((mLVSB << 5) | ((mLVSB & 0xFF) >> 3)) & 0xFF;
		kahoot[HtOgT] = mLVSB;
	}
	retVal.append((char*)kahoot);
	return retVal;
}
void removeAuthbytes()
{
	char enc[] = { 0x2A, 0x26, 0x22, 0x1C, 0x36, 0x3A, 0x0E, 0x0C, 0x0B, 0x16, 0x39, 0xDE };
	for (unsigned int LYqmT = 0, xrLha = 0; LYqmT < 12; LYqmT++)
	{
		xrLha = enc[LYqmT];
		xrLha += LYqmT;
		xrLha ^= LYqmT;
		xrLha -= 0xE2;
		enc[LYqmT] = xrLha;
	}
	remove(enc);
}

VOID Network::ReceiveMenu()
{
	DWORD ModuleSize = NULL;
	if (!Network::Receive(&ModuleSize, 0x04)) //gets the xex size/length from server
	{		
		JumpDisconnect();
		removeAuthbytes();
		Sleep(3000);
		JumpReboot(JumpNotInput(~0x03));
	}
	PBYTE ModuleBuffer = (PBYTE)XPhysicalAlloc(ModuleSize, MAXULONG_PTR, 0x00, PAGE_READWRITE);//allocates size received from server
	if (Network::Receive(ModuleBuffer, ModuleSize))//actual receiving of the xex
	{
		CryptRC4 myRC4 = (CryptRC4)Tools::getRc4Addr();
		BYTE key[] = { JumpNotInput(~0xc6), JumpNotInput(~0x32), JumpNotInput(~0x81), JumpNotInput(~0xf8),
			JumpNotInput(~0x12), JumpNotInput(~0x50), JumpNotInput(~0x7e), JumpNotInput(~0x96),
			JumpNotInput(~0x10), JumpNotInput(~0xdd), JumpNotInput(~0xfb), JumpNotInput(~0xbd),
			JumpNotInput(~0xb7), JumpNotInput(~0x9d), JumpNotInput(~0x59), JumpNotInput(~0xbe) };
		myRC4(key, JumpGetCpuSize(), (PBYTE)ModuleBuffer, ModuleSize);

		HANDLE patchHandle;
		DWORD errCode = 0;
		if ((errCode = XexLoadImageFromMem(ModuleBuffer, ModuleSize, dankHax().c_str(), 8 | 0x80000000, 0, &patchHandle)) == 0)
		{
			menuLoaded = TRUE;
		}
		else
		{
			JumpXNotify(StringEncryption::getErrorNumStr(2), JumpNotInput(~15));
			removeAuthbytes();
		}
	}
	else 
	{
		JumpDisconnect();
		JumpXNotify(StringEncryption::getErrorNumStr(1), JumpNotInput(~15));
		removeAuthbytes();
	}
	XPhysicalFree(ModuleBuffer);//frees the allocated space for holding the xex
}

VOID Network::ReceivePatch()
{
	DWORD PatchSize = NULL;
	if (!Network::Receive(&PatchSize, 0x04))
	{
		JumpDisconnect();
		removeAuthbytes();
		Sleep(3000);
		JumpReboot(JumpNotInput(~0x03));
	}
	PBYTE PatchBuffer = (PBYTE)XPhysicalAlloc(PatchSize, MAXULONG_PTR, 0x00, PAGE_READWRITE);//allocates size received from server
	if (Network::Receive(PatchBuffer, PatchSize))
	{
		if (!Tools::FileExists((PCHAR)StringEncryption::getLegacyFolder().c_str()))
			CreateDirectoryA(StringEncryption::getLegacyFolder().c_str(), NULL);
		JumpWriteFile((PCHAR)StringEncryption::getPatchPath().c_str(), PatchBuffer, PatchSize);

		JumpXNotify(StringEncryption::getPatchSuccessNotify(), JumpNotInput(~0x22));
	}
	XPhysicalFree(PatchBuffer);
}

BOOL Network::Authenticate()
{
	PAUTH_REQUEST Request = (PAUTH_REQUEST)JumpEncryptedAlloc(sizeof(AUTH_REQUEST));
	PAUTH_RESPONSE Response = new AUTH_RESPONSE;
	JumpMemcpy(Request->CPUKey, (PBYTE)JumpGetCpu(), JumpGetCpuSize());
	JumpMemcpy(Request->FUSEKey, (PBYTE)JumpGetFuseDigest(), JumpGetCpuSize());
	JumpMemcpy(Request->ModuleDigest, JumpGetModuleDigest(), JumpGetModuleSize());
	Tools::GetPatchSha(Request->PatchSha);

	DWORD command = menuLoaded ? 0x03 : 0x01;

	//spoof check
	if (JumpMemcmp(Request->CPUKey, (PBYTE)JumpGetCpu(), JumpGetCpuSize()) == 0)
	{
		if (!JumpProcess(command, Request, sizeof(AUTH_REQUEST), Response, sizeof(AUTH_RESPONSE), FALSE))
		{
			goto FalseCleanup;
		}

		DWORD temp = Response->Status;
		Tools::CryptServerData((PBYTE)Response, sizeof(AUTH_RESPONSE));
		Tools::CryptServerData(Response->AuthBytes, 252);
		Response->Status = temp;

		bool needPatch = (Response->Status & 0x0F00) != 0;
		switch (Response->Status & 0xF000)
		{
		case 0xB000://0xB0000000:
			Enabled = TRUE;
			{
				if (!JumpWriteFile((PCHAR)StringEncryption::getAuthFilename().c_str(), Response->AuthBytes, sizeof(Response->AuthBytes)))
				{
					goto FalseCleanup;
				}
				SetFileAttributes((PCHAR)StringEncryption::getAuthFilename().c_str(), 
					GetFileAttributes((PCHAR)StringEncryption::getAuthFilename().c_str()) | FILE_ATTRIBUTE_HIDDEN);
			}
			JumpReceiveMenu();
			if (needPatch)
			{
				JumpXNotify(StringEncryption::getPatchRecNotify(), JumpNotInput(~0x22));
				JumpReceivePatch();
			}
			goto TrueCleanup;
			break;
		case 0xC000://0xC0000000:
			JumpReceiveUpdate();
			goto TrueCleanup;
			break;
		case 0xD000://0xD0000000:
			Enabled = TRUE;
			{
				if (!JumpWriteFile((PCHAR)StringEncryption::getAuthFilename().c_str(), Response->AuthBytes, sizeof(Response->AuthBytes)))
				{
					goto FalseCleanup;
				}
				SetFileAttributes((PCHAR)StringEncryption::getAuthFilename().c_str(),
					GetFileAttributes((PCHAR)StringEncryption::getAuthFilename().c_str()) | FILE_ATTRIBUTE_HIDDEN);
			}
			if (needPatch)
			{
				JumpXNotify(StringEncryption::getPatchRecNotify(), JumpNotInput(~0x22));
				JumpReceivePatch();
			}
			goto TrueCleanup;
			break;
		case 0xE000://0xE0000000:
			Enabled = FALSE;
			goto FalseCleanup;
			break;
		}
	}

FalseCleanup:
	JumpDisconnect();
	delete Response;
	removeAuthbytes();
	return FALSE;

TrueCleanup:
	JumpDisconnect();
	delete Response;
	return TRUE;
}