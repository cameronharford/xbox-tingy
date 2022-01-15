#include "stdafx.h"
#include <string>
#include "Hooks.h"
#include "Tools.h"
#include "kernel.h"
#include "StringEncryption.h"
#include <algorithm>
#include <iterator>
#include <vector>

typedef NTSTATUS(__cdecl *JumpTableEnt)(...);
JumpTableEnt *HookJumpTable = new JumpTableEnt[14];
#define JumpOpenHook		HookJumpTable[0]
#define JumpBufDiff2		HookJumpTable[1]
#define JumpHookFuncStart	HookJumpTable[2]
#define JumpOpenStub		HookJumpTable[3]
#define JumpFind			HookJumpTable[4]
#define JumpReadStub		HookJumpTable[5]
#define JumpCloseHook		HookJumpTable[6]
#define JumpHasSuffix		HookJumpTable[7]
#define JumpQueryStub		HookJumpTable[8]
#define JumpQueryHook		HookJumpTable[9]
#define JumpReplaceBuffer	HookJumpTable[10]
#define JumpCloseStub		HookJumpTable[11]
#define JumpAddedDword		HookJumpTable[12]
#define JumpReadHook		HookJumpTable[13]

std::vector<HANDLE> xamHandles;
MemoryBuffer* patchBuffer = NULL;
bool patchLoaded = false;

static LONG getFilePointer(HANDLE fileHandle)
{
	DWORD lastErr = GetLastError();

	DWORD pos = SetFilePointer(fileHandle, 0, NULL, FILE_CURRENT);
	
	if (pos == INVALID_SET_FILE_POINTER)
	{
		if (GetLastError() == ERROR_NEGATIVE_SEEK && lastErr != ERROR_NEGATIVE_SEEK)
		{
			//we have a problem...
			//DbgPrint3("Error getting file ptr");
			//throw new std::exception();
		}
		else
		{
			//try using a LARGE_INTEGER this time
			//DbgPrint3("Using Large Int instead");
			LARGE_INTEGER temp;
			temp.QuadPart = 0;
			temp.LowPart = SetFilePointer(fileHandle, temp.LowPart, &temp.HighPart, FILE_CURRENT);
			return temp.HighPart << 32 | temp.LowPart;
		}
	}
	return pos;
}
static bool findJump(HANDLE hand)
{
	return std::find(xamHandles.begin(), xamHandles.end(), hand) != xamHandles.end();
}
static bool has_suffix(const std::string &str, const std::string &suffix)\
{
	return str.size() >= suffix.size() &&
		str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}
#pragma region NtQueryInformation Hook
typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,   // 2
	FileBothDirectoryInformation,   // 3
	FileBasicInformation,           // 4
	FileStandardInformation,        // 5
	FileInternalInformation,        // 6
	FileEaInformation,              // 7
	FileAccessInformation,          // 8
	FileNameInformation,            // 9
	FileRenameInformation,          // 10
	FileLinkInformation,            // 11
	FileNamesInformation,           // 12
	FileDispositionInformation,     // 13
	FilePositionInformation,        // 14
	FileFullEaInformation,          // 15
	FileModeInformation,            // 16
	FileAlignmentInformation,       // 17
	FileAllInformation,             // 18
	FileAllocationInformation,      // 19
	FileEndOfFileInformation,       // 20
	FileAlternateNameInformation,   // 21
	FileStreamInformation,          // 22
	FilePipeInformation,            // 23
	FilePipeLocalInformation,       // 24
	FilePipeRemoteInformation,      // 25
	FileMailslotQueryInformation,   // 26
	FileMailslotSetInformation,     // 27
	FileCompressionInformation,     // 28
	FileObjectIdInformation,        // 29
	FileCompletionInformation,      // 30
	FileMoveClusterInformation,     // 31
	FileQuotaInformation,           // 32
	FileReparsePointInformation,    // 33
	FileNetworkOpenInformation,     // 34
	FileAttributeTagInformation,    // 35
	FileTrackingInformation,        // 36
	FileIdBothDirectoryInformation, // 37
	FileIdFullDirectoryInformation, // 38
	FileValidDataLengthInformation, // 39
	FileShortNameInformation,       // 40
	FileMaximumInformation

} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
typedef struct _FILE_NETWORK_OPEN_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;
__declspec(naked) NTSTATUS QueryInfoStub(
	IN		HANDLE FileHandle,
	OUT		PIO_STATUS_BLOCK IoStatusBlock,
	OUT		PVOID FileInformation,
	IN		DWORD Length,
	IN		FILE_INFORMATION_CLASS FileInformationClass)
{
	__asm
	{
		mr		  r11, r4
		slwi      r10, r11, 3
		add       r11, r11, r10
		srwi      r10, r11, 11
		xor r11, r10, r11
		slwi      r10, r11, 15
		add       r3, r10, r11
		blr
	}
}
NTSTATUS QueryInfoHook(
	IN		HANDLE FileHandle,
	OUT		PIO_STATUS_BLOCK IoStatusBlock,
	OUT		PVOID FileInformation,
	IN		DWORD Length,
	IN		FILE_INFORMATION_CLASS FileInformationClass)
{
	NTSTATUS status = JumpQueryStub(
		FileHandle,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass
	);
	if (patchLoaded && JumpFind(FileHandle))//JumpFind(FileHandle))
	{
		if (Length == 0x38 && FileInformation != NULL)
		{
			PFILE_NETWORK_OPEN_INFORMATION tempPtr = (PFILE_NETWORK_OPEN_INFORMATION)FileInformation;
			tempPtr->AllocationSize.QuadPart = 0x2401000;// 0x02426000;
			tempPtr->EndOfFile.QuadPart = 0x2401000;// 0x02426000;
		}
	}
	return status;
}
#pragma endregion
#pragma region NtClose
__declspec(naked) NTSTATUS CloseFileStub(HANDLE FileHandle)
{
	__asm
	{
		srwi      r9, r4, 2
		mr        r11, r5
		cmplwi    cr6, r9, 0
		beq       cr6, loc
		addi      r10, r3, -4
		mtctr     r9
loc:
		lwzu      r3, 4(r10)
		blr
	}
}
NTSTATUS CloseFileHook(HANDLE Handle)
{
	auto place = std::find(xamHandles.begin(), xamHandles.end(), Handle);
	if (place != xamHandles.end())
	{
		xamHandles.erase(place);
		//DbgPrint3("Closed handle");
	}
	return JumpCloseStub(Handle);
}
#pragma endregion
#pragma region NtReadFile
__declspec(naked) NTSTATUS ReadFileStub(
	HANDLE FileHandle,//r3
	HANDLE Event OPTIONAL,//r4
	PIO_APC_ROUTINE ApcRoutine OPTIONAL,//r5
	PVOID ApcContext OPTIONAL,//r6
	PIO_STATUS_BLOCK IoStatusBlock,//r7
	PVOID Buffer,//r8
	DWORD Length,//r9
	PLARGE_INTEGER ByteOffset OPTIONAL)//r10
{
	__asm
	{
		mflr r12
		stw r12, -8(r1)
		stwu r1, -0x20(r1)
		stw r3, 0x8(r1)
		stw r4, 0xC(r1)
loc:
		addi r3, r3, 0x4
		cmplw cr6, r3, r4
		blt loc
		clrlwi r3, r11, 24
		addi r1, r1, 0x20
		lwz r12, -8(r1)
		mtlr r12
		blr
	}
}

//This function exists so that every ntreadfile call doesn't have
//to make tons of extra stack space due to all the local variables
//I use in the hook. I would think it would cause issues if all of
//the variables were in the hook itself, much like how the massive
//ironman func in Legacy has an enormous stack allocation and has
//various glitches.

PBYTE garbageBuffer = new BYTE[16];

NTSTATUS checkForBufDiff2(
	HANDLE FileHandle,//r3
	HANDLE Event OPTIONAL,//r4
	PIO_APC_ROUTINE ApcRoutine OPTIONAL,//r5
	PVOID ApcContext OPTIONAL,//r6
	PIO_STATUS_BLOCK IoStatusBlock,//r7
	PVOID Buffer,//r8
	DWORD Length,//r9
	PLARGE_INTEGER ByteOffset OPTIONAL)//r10
{
	NTSTATUS status = 0;
	DWORD offset = 0;

	//First check if we need to adjust the byteoffset to prevent
	//reading past the end of the dlc file.
	if (ByteOffset != NULL)
		offset = ByteOffset->QuadPart;
	else
	{
		//offset is null, so get internal file pointer position
		LONG pos = getFilePointer(FileHandle);
		offset = pos;
	}
	//check if we need to replace the ReadFile buffer with our own patch
	if (JumpReplaceBuffer((PBYTE)Buffer, offset, Length))
	{
		//spoof the info (# of bytes read by ReadFile call)
		IoStatusBlock->Information = Length;
		status = 0;

		IO_STATUS_BLOCK garbageBlock;
		LARGE_INTEGER tempLargeInt;
		tempLargeInt.QuadPart = 0x1000;

		//signal the event handle (so it doesn't hang around waiting)
		JumpReadStub(
			FileHandle,
			Event,
			ApcRoutine,
			ApcContext,
			&garbageBlock,
			garbageBuffer,
			4UL,
			&tempLargeInt);
	}
	else
		status = JumpReadStub(
			FileHandle,
			Event,
			ApcRoutine,
			ApcContext,
			IoStatusBlock,
			Buffer,
			Length,
			ByteOffset);

	return status;
}
NTSTATUS ReadFileHook(
	HANDLE FileHandle,//r3
	HANDLE Event OPTIONAL,//r4
	PIO_APC_ROUTINE ApcRoutine OPTIONAL,//r5
	PVOID ApcContext OPTIONAL,//r6
	PIO_STATUS_BLOCK IoStatusBlock,//r7
	PVOID Buffer,//r8
	DWORD Length,//r9
	PLARGE_INTEGER ByteOffset OPTIONAL)//r10
{
	if (patchLoaded && JumpFind(FileHandle))
		return JumpBufDiff2(
			FileHandle,
			Event,
			ApcRoutine,
			ApcContext,
			IoStatusBlock,
			Buffer,
			Length,
			ByteOffset);
	else
		return JumpReadStub(
			FileHandle,
			Event,
			ApcRoutine,
			ApcContext,
			IoStatusBlock,
			Buffer,
			Length,
			ByteOffset);
}
#pragma endregion
#pragma region NtOpenFile
#pragma region DlcNameDecryption
std::string getDlcExtension()
{
	//returns a string with C4D0E661EFFDF372ECC8DDA324B6205EAED3D7F354
	//C4D0E6 61EFFD F372EC C8DDA3 24B620 5EAED3 D7F354
	std::string retVal;

	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// part1 = "C4D0E6"
	unsigned char part1[7] = { 0x8C, 0x7E, 0x8F, 0x7C, 0x92, 0x84, 0x4F };
	for (unsigned int dfnMI = 0, CPhBS = 0; dfnMI < 7; dfnMI++)
	{
		CPhBS = part1[dfnMI];
		CPhBS -= 0x4A;
		CPhBS -= dfnMI;
		CPhBS++;
		part1[dfnMI] = CPhBS;
	}
	retVal.append((char*)part1);

	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// part2 = "61EFFD"
	unsigned char part2[7] = { 0x6B, 0x60, 0x87, 0x88, 0x87, 0x82, 0xF9 };
	for (unsigned int bYJvI = 0, SDOYu = 0; bYJvI < 7; bYJvI++)
	{
		SDOYu = part2[bYJvI];
		SDOYu += bYJvI;
		SDOYu++;
		SDOYu = (((SDOYu & 0xFF) >> 1) | (SDOYu << 7)) & 0xFF;
		part2[bYJvI] = SDOYu;
	}
	retVal.append((char*)part2);

	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// part3 = "F372EC"
	unsigned char part3[7] = { 0x8B, 0x62, 0x6B, 0x66, 0x91, 0x86, 0x0D };
	for (unsigned int xcpKt = 0, GXkPR = 0; xcpKt < 7; xcpKt++)
	{
		GXkPR = part3[xcpKt];
		GXkPR -= xcpKt;
		GXkPR = (((GXkPR & 0xFF) >> 1) | (GXkPR << 7)) & 0xFF;
		GXkPR ^= 0x83;
		part3[xcpKt] = GXkPR;
	}
	retVal.append((char*)part3);

	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// part4 = "C8DDA3"
	unsigned char part4[7] = { 0xF2, 0x1F, 0xEE, 0xEE, 0xFA, 0x33, 0xFF };
	for (unsigned int SYzrP = 0, ZBWND = 0; SYzrP < 7; SYzrP++)
	{
		ZBWND = part4[SYzrP];
		ZBWND = ~ZBWND;
		ZBWND = (((ZBWND & 0xFF) >> 2) | (ZBWND << 6)) & 0xFF;
		part4[SYzrP] = ZBWND;
	}
	retVal.append((char*)part4);

	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// part5 = "24B620"
	unsigned char part5[7] = { 0x32, 0x36, 0x42, 0x38, 0x3A, 0x3A, 0x0C };
	for (unsigned int LJDGX = 0, fhbDz = 0; LJDGX < 7; LJDGX++)
	{
		fhbDz = part5[LJDGX];
		fhbDz -= LJDGX;
		fhbDz ^= LJDGX;
		part5[LJDGX] = fhbDz;
	}
	retVal.append((char*)part5);

	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// part6 = "5EAED3"
	unsigned char part6[7] = { 0xFC, 0x84, 0x03, 0x85, 0x82, 0x7D, 0x65 };
	for (unsigned int PDxfV = 0, zoNOl = 0; PDxfV < 7; PDxfV++)
	{
		zoNOl = part6[PDxfV];
		zoNOl += 0x9E;
		zoNOl = (((zoNOl & 0xFF) >> 7) | (zoNOl << 1)) & 0xFF;
		zoNOl ^= PDxfV;
		part6[PDxfV] = zoNOl;
	}
	retVal.append((char*)part6);

	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// part7 = "D7F354"
	unsigned char part7[7] = { 0x50, 0xE7, 0x60, 0xC7, 0xD7, 0xCF, 0x36 };
	for (unsigned int zJSID = 0, uDMmv = 0; zJSID < 7; zJSID++)
	{
		uDMmv = part7[zJSID];
		uDMmv++;
		uDMmv = (((uDMmv & 0xFF) >> 3) | (uDMmv << 5)) & 0xFF;
		uDMmv += 0x1A;
		part7[zJSID] = uDMmv;
	}
	retVal.append((char*)part7);

	return retVal;
}
std::string extension = getDlcExtension();
static bool checkSuffix(char* Buffer)
{
	std::string fileStr(Buffer);
	return has_suffix(fileStr, extension);
}
#pragma endregion
__declspec(naked) NTSTATUS OpenFileStub(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	DWORD ShareAccess,
	DWORD OpenOptions)
{
	__asm
	{
		lis r11, 0x9912
		ori r11, r11, 0x653
		xor r5, r8, r11
		xor	r4, r7, r5
		srwi r5, r5, 8
		clrlslwi r8, r4, 24, 2
		add r3, r8, r5
		blr
	}
}
NTSTATUS OpenFileHook(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	DWORD ShareAccess,
	DWORD OpenOptions)
{
	NTSTATUS status = JumpOpenStub(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		ShareAccess,
		OpenOptions);

	if (ObjectAttributes != NULL)
	{
		if (JumpHasSuffix(ObjectAttributes->ObjectName->Buffer))
		{
			xamHandles.push_back(*FileHandle);
		}
	}
	return status;
}
#pragma endregion
#pragma region Jump Table Stuff
typedef void * (__cdecl *ThumpContinuation)(...);
void *SetupJumpTable()
{
	JumpOpenHook = (JumpTableEnt)OpenFileHook;
	JumpHookFuncStart = (JumpTableEnt)Tools::HookFunctionStart;
	JumpOpenStub = (JumpTableEnt)OpenFileStub;
	JumpReadStub = (JumpTableEnt)ReadFileStub;
	JumpCloseHook = (JumpTableEnt)CloseFileHook;
	JumpQueryStub = (JumpTableEnt)QueryInfoStub;
	JumpQueryHook = (JumpTableEnt)QueryInfoHook;
	JumpCloseStub = (JumpTableEnt)CloseFileStub;
	JumpAddedDword = (JumpTableEnt)Tools::getAddedValueDWORD;
	JumpReadHook = (JumpTableEnt)ReadFileHook;

	JumpBufDiff2 = (JumpTableEnt)checkForBufDiff2;
	JumpHasSuffix = (JumpTableEnt)checkSuffix;
	JumpReplaceBuffer = (JumpTableEnt)Hooks::replaceBuffer;
	JumpFind = (JumpTableEnt)findJump;
	return NULL;
}
void* garbagePtr2 = SetupJumpTable();
#pragma endregion
void* setupCloseFileHook();
void* setupReadFileHook();
void* setupOpenFileHook()
{
	//openfile
	DWORD addr = 0x8B492115;
	addr ^= JumpAddedDword(0x8d824f20, 0x88d6e4bc, JumpAddedDword(13, 7, 1));
	addr ^= JumpAddedDword(0x80cd04c5, 0x83c5afc0, JumpAddedDword(2, 2, 0));
	JumpHookFuncStart((PDWORD)addr, (PDWORD)JumpOpenStub, (DWORD)JumpOpenHook);
	return NULL;
}
void* setupCloseFileHook()
{
	//closefile
	DWORD addr = 0x8B477DB5;
	addr ^= JumpAddedDword(0x8d824f20, 0x88d6e4bc, JumpAddedDword(13, 7, 1));
	addr ^= JumpAddedDword(0x80cd04c5, 0x83c5afc0, JumpAddedDword(2, 2, 0));
	JumpHookFuncStart((PDWORD)addr, (PDWORD)JumpCloseStub, (DWORD)JumpCloseHook);
	return setupReadFileHook;
}
void* setupQueryInfoHook()
{
	//queryinfofile
	DWORD addr = 0x81DB36BD;
	addr ^= JumpAddedDword(0x88d6e4bc, 0x80cd04c5, JumpAddedDword(2, 2, 0));
	addr ^= JumpAddedDword(0x8d824f20, 0x892f0400, JumpAddedDword(13, 7, 1));
	JumpHookFuncStart((PDWORD)addr, (PDWORD)JumpQueryStub, (DWORD)JumpQueryHook);
	return setupCloseFileHook;
}
void* setupReadFileHook()
{
	//readfile
	DWORD addr = 0x8FEB6A1F;
	addr ^= JumpAddedDword(0x85a90427, 0x83c5afc0, JumpAddedDword(2, 2, 0));
	addr ^= JumpAddedDword(0x8a140bf5, 0x8d824f20, JumpAddedDword(13, 7, 1));
	JumpHookFuncStart((PDWORD)addr, (PDWORD)JumpReadStub, (DWORD)JumpReadHook);
	return setupOpenFileHook;
}
void Hooks::loadKernelHooks()
{
	ThumpContinuation cont = (ThumpContinuation)setupQueryInfoHook;

	//like a linked list of functions
	while (cont != NULL)
		cont = (ThumpContinuation)cont();
}

//container for patch listings, located at beginning of patch file
class PatchListing
{
public:
	DWORD lowEnd;
	DWORD highEnd;
	DWORD fileOffset;
	DWORD getSize() { return highEnd - lowEnd; }
	bool isInRange(DWORD off, DWORD len) { return off >= lowEnd && off + len <= highEnd; }
};
PatchListing* patches;

//basic decrypt class to unxor the patch's secondary encryption
class PatchDec
{
public:
	static void decrypt(PBYTE values, DWORD len)
	{
		if (values != NULL)
		{
			for (int i = 0; i < len; i++)
				values[i] = (values[i] + 0x11) ^ 0xf6;
		}
	}

	static DWORD decrypt(DWORD value)
	{
		BYTE vals[4];
		vals[0] = (value >> 24);
		vals[1] = (value >> 16);
		vals[2] = (value >> 8);
		vals[3] = (value);
		decrypt(vals, 4);
		return (vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | (vals[3]);
	}
};

//loads the patch via CReadFile("HDD:\\Legacy\\patch")
void Hooks::loadPatch()
{
	if (!patchLoaded)
	{
		patchBuffer = new MemoryBuffer();
		if (Tools::CReadFile((PCHAR)StringEncryption::getPatchPath().c_str(), *patchBuffer))
		{
			Tools::CryptPatchData(patchBuffer->GetBuffer(), patchBuffer->GetLength());

			//first offset is the number of listings
			DWORD numListings = PatchDec::decrypt(*(DWORD*)patchBuffer->GetBuffer());
			patches = new PatchListing[numListings];
			DWORD* ptr = (DWORD*)patchBuffer->GetBuffer();
			for (DWORD i = 0, j = 1; j < (numListings * 3); j += 3)
			{
				patches[i].lowEnd = PatchDec::decrypt(ptr[j]);
				patches[i].highEnd = PatchDec::decrypt(ptr[j + 1]);
				patches[i].fileOffset = PatchDec::decrypt(ptr[j + 2]);
				i++;
			}
			patchLoaded = true;
		}
	}
}

//direct load of patch from buffer
void Hooks::loadPatch(PBYTE Buffer, DWORD len)
{
	patchBuffer = new MemoryBuffer();
	if (Buffer != NULL && len > 0)
	{
		patchBuffer->Add(Buffer, len);

		//first offset is the number of listings
		DWORD numListings = *(DWORD*)patchBuffer->GetBuffer();
		patches = new PatchListing[numListings];
		DWORD* ptr = (DWORD*)patchBuffer->GetBuffer();
		for (DWORD i = 0, j = 1; j < (numListings * 3); j += 3)
		{
			patches[i].lowEnd = ptr[j];//ptr[j];
			patches[i].highEnd = ptr[j + 1];
			patches[i].fileOffset = ptr[j + 2];
			i++;
		}
		patchLoaded = true;
	}
}
bool Hooks::replaceBuffer(PBYTE Buffer, DWORD Offset, DWORD Length)
{
	DWORD numListings = PatchDec::decrypt(*(DWORD*)patchBuffer->GetBuffer());
	for (DWORD i = 0; i < numListings; i++)
	{
		if (patches[i].isInRange(Offset, Length))
		{
			DWORD fOffset = ((DWORD)patchBuffer->GetBuffer()) + patches[i].fileOffset;
			fOffset += (Offset - patches[i].lowEnd);
			memcpy(Buffer, (PBYTE)fOffset, Length);
			PatchDec::decrypt(Buffer, Length);
			return true;
		}
	}
	return false;
}
