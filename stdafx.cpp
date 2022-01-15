// stdafx.cpp : source file that includes just the standard includes
// NativeDLL.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "stdafx.h"
#include <stdio.h>
#include <fstream>
//#define DEBUG

// TODO: reference additional headers your program requires here

#ifdef PERSONAL
#define PRINT_WITH_LOG

#ifndef PRINT_WITH_LOG
void DbgPrint(const char * _Format, ...)
{
	char buffer1[1000];

	va_list ap;
	va_start(ap, _Format);
	vsprintf_s(buffer1, sizeof(buffer1), _Format, ap);
	va_end(ap);
	printf("%s\n", buffer1);
}
#else
CRITICAL_SECTION dbgLock;
BOOL dbgInit = FALSE;

void DbgPrint(const char* strFormat, ...) {

	if (dbgInit == FALSE) {
		InitializeCriticalSection(&dbgLock);
		dbgInit = TRUE;

		//remove the old log
		remove("HDD:\\MiscLog.log");
	}

	CHAR buffer[1000];

	va_list pArgList;
	va_start(pArgList, strFormat);
	vsprintf_s(buffer, 1000, strFormat, pArgList);
	va_end(pArgList);

	printf("%s\n", buffer);

	EnterCriticalSection(&dbgLock);
	std::ofstream writeLog;
	writeLog.open("HDD:\\MiscLog.log", std::ofstream::app);
	if (writeLog.is_open())
	{
		writeLog.write(buffer, strlen(buffer));
		writeLog.write("\r\n", 2);
	}
	writeLog.close();
	LeaveCriticalSection(&dbgLock);
}
#endif
#else
#define DbgPrint()
#endif