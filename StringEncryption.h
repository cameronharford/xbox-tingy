#pragma once
#include "stdafx.h"
#include <string>

using namespace std;

class StringEncryption
{
public:
	//ANSI strings for file operations
	static string getLegacy();//Legacy
	static string getLegacyMenu();//LegacyMenu.xex
	static string getHdd();//HDD:\\ 
	static string getFullHddPath();// \\Device\\Harddisk0\\Partition1
	static string getLegacyMenuPath();//HDD:\\LegacyMenu.xex
	static string getLegacyFolder();//HDD:\\Legacy
	static string getPatchPath();//HDD:\\Legacy\\patch
	static string getSymbLinkPrefix(BOOL system);
	static string getAuthFilename();

	//UNICODE strings for xnotify messages
	static PWCHAR getPatchRecNotify();//L"Receiving Legacy patch. Please wait"
	static PWCHAR getPatchSuccessNotify();//L"Legacy patch downloaded"
	static wstring getErrorStr();//L"Error "
	static PWCHAR getErrorNumStr(int num);//for Error 1, 2, 3 (appending a number)
	static PWCHAR getDigestErrorStr();//L"Couldn't get module digest"
	static PWCHAR getUpdError();//L"Couldn't receive update"
	static PWCHAR getUpdWriteError();//L"Couldn't write update to xex"
	static PWCHAR getUpdCmpl();//L"Legacy Menu - Update Complete. Rebooting Now..."
	static PWCHAR getGamesaveErr();//L"Couldn't write gamesave to console"
	static PWCHAR getGamesaveWrite();//L"Wrote gamesave to console"
	static PWCHAR getGamesaveRecErr();//L"Couldn't receive gamesave"
};

