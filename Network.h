#ifndef _NETWORK_H
#define _NETWORK_H

#pragma once
#include "stdafx.h"
#include "Tools.h"

typedef enum _XNCALLER_TYPE : DWORD {
	XNCALLER_INVALID = 0x00,
	XNCALLER_TITLE = 0x01,
	XNCALLER_SYSAPP = 0x02,
	XNCALLER_XBDM = 0x03,
	XNCALLER_TEST = 0x04,
} XNCALLER_TYPE;

#pragma pack(1)
typedef struct _AUTH_REQUEST {
	BYTE PatchSha[0x14];
	BYTE FUSEKey[0x10];
	BYTE ModuleDigest[0x14];
	BYTE CPUKey[0x10];
	//bool needPatch;
} AUTH_REQUEST, *PAUTH_REQUEST;
typedef struct _AUTH_RESPONSE {
	DWORD Status;
	BYTE AuthBytes[252];
} AUTH_RESPONSE, *PAUTH_RESPONSE;
typedef struct _GOBALS_REQUEST {
	BYTE FUSEKey[0x10];
	BYTE ModuleDigest[0x14];
	BYTE CPUKey[0x10];
	BYTE ProfileID[0x8];
	//BYTE SALT[0x10];//use the 2 part [1] of another console fuse/salt to encrypt the bytes on the server, then decrypt them with the same part of the salt on the console
} GOBALS_REQUEST, *PGOBALS_REQUEST;
typedef struct _GOBALS_RESPONSE {
	DWORD Status;
} GOBALS_RESPONSE, *PGOBALS_RESPONSE;
#pragma pack()
static SOCKET m_Socket;
//static BOOL Connected;
static BOOL menuLoaded = FALSE;

static BYTE IP[0x04] = { 0x4A, 0x5B, 0x70, 0x03 };
static WORD Port = 6550;// 6542;//2456;

class Network {
public:
	static SOCKET Connect();
	static VOID Disconnect();
	static BOOL Send(DWORD Command, PVOID Buffer, DWORD Length);
	static BOOL Receive(PVOID Buffer, DWORD Length);
	static BOOL Process(DWORD Command, PVOID Request, DWORD RequestLength, PVOID Response, DWORD ResponseLength, BOOL Close = TRUE);
	static VOID ReceiveUpdate();
	static VOID ReceiveMenu();
	static VOID ReceivePatch();
	static BOOL Authenticate();
};

static SOCKET (_cdecl *NetDll_socket)(XNCALLER_TYPE Xnc, DWORD Af, DWORD Type, DWORD Protocol)
	= (SOCKET(*)(XNCALLER_TYPE, DWORD, DWORD, DWORD))resolveXamExport(0x03);
	//= (SOCKET(*)(XNCALLER_TYPE, DWORD, DWORD, DWORD))Tools::ResolveFunction("xam.xex", 0x03);

static DWORD (_cdecl *NetDll_closesocket)(XNCALLER_TYPE Xnc, SOCKET s)
	= (DWORD(*)(XNCALLER_TYPE, SOCKET))resolveXamExport(0x04);
	//= (DWORD(*)(XNCALLER_TYPE, SOCKET))Tools::ResolveFunction("xam.xex", 0x04);

static DWORD (_cdecl *NetDll_shutdown)(XNCALLER_TYPE Xnc, SOCKET s, DWORD Method)
	= (DWORD(*)(XNCALLER_TYPE, SOCKET, DWORD))resolveXamExport(0x05);
	//= (DWORD(*)(XNCALLER_TYPE, SOCKET, DWORD))Tools::ResolveFunction("xam.xex", 0x05);

static DWORD (_cdecl *NetDll_setsockopt)(XNCALLER_TYPE Xnc, SOCKET s, DWORD Level, DWORD Option, CONST PCHAR Value, DWORD Length)
	= (DWORD(*)(XNCALLER_TYPE, SOCKET, DWORD, DWORD, CONST PCHAR, DWORD))resolveXamExport(0x07);
	//= (DWORD(*)(XNCALLER_TYPE, SOCKET, DWORD, DWORD, CONST PCHAR, DWORD))Tools::ResolveFunction("xam.xex", 0x07);

static DWORD (_cdecl *NetDll_connect)(XNCALLER_TYPE Xnc, SOCKET s, CONST struct sockaddr *Name, DWORD Length)
	= (DWORD(*)(XNCALLER_TYPE, SOCKET, CONST struct sockaddr*, DWORD))resolveXamExport(0x0C);
	//= (DWORD(*)(XNCALLER_TYPE, SOCKET, CONST struct sockaddr*, DWORD))Tools::ResolveFunction("xam.xex", 0x0C);

static DWORD (_cdecl *NetDll_recv)(XNCALLER_TYPE Xnc, SOCKET s, CONST CHAR FAR *Buffer, DWORD Length, DWORD Flags)
	= (DWORD(*)(XNCALLER_TYPE, SOCKET, CONST CHAR FAR*, DWORD, DWORD))resolveXamExport(0x12);
	//= (DWORD(*)(XNCALLER_TYPE, SOCKET, CONST CHAR FAR*, DWORD, DWORD))Tools::ResolveFunction("xam.xex", 0x12);

static DWORD (_cdecl *NetDll_send)(XNCALLER_TYPE Xnc, SOCKET s, CONST CHAR FAR *Buffer, DWORD Length, DWORD Flags)
	= (DWORD(*)(XNCALLER_TYPE, SOCKET, CONST CHAR FAR*, DWORD, DWORD))resolveXamExport(0x16);
	//= (DWORD(*)(XNCALLER_TYPE, SOCKET, CONST CHAR FAR*, DWORD, DWORD))Tools::ResolveFunction("xam.xex", 0x16);

static DWORD (_cdecl *NetDll_WSAStartupEx)(XNCALLER_TYPE Xnc, WORD VersionA, LPWSADATA Wsad, DWORD VersionB)
	= (DWORD(*)(XNCALLER_TYPE, WORD, LPWSADATA, DWORD))resolveXamExport(0x24);
	//= (DWORD(*)(XNCALLER_TYPE, WORD, LPWSADATA, DWORD))Tools::ResolveFunction("xam.xex", 0x24);

static DWORD (_cdecl *NetDll_XNetStartup)(XNCALLER_TYPE Xnc, XNetStartupParams *Xnsp)
	= (DWORD(*)(XNCALLER_TYPE, XNetStartupParams*))resolveXamExport(0x33);
	//= (DWORD(*)(XNCALLER_TYPE, XNetStartupParams*))Tools::ResolveFunction("xam.xex", 0x33);

#endif