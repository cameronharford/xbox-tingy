#include "stdafx.h"
#include "StringEncryption.h"

#pragma region ANSI Strings
string StringEncryption::getLegacy()
{
	string retVal;
	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// cP2 = "Legacy"
	unsigned char cP2[7] = { 0xF6, 0x87, 0xA6, 0x45, 0x64, 0xC4, 0x2C };
	for (unsigned int LXBSG = 0, IJBOz = 0; LXBSG < 7; LXBSG++)
	{
		IJBOz = cP2[LXBSG];
		IJBOz -= 0x32;
		IJBOz += LXBSG;
		IJBOz = (((IJBOz & 0xFF) >> 4) | (IJBOz << 4)) & 0xFF;
		cP2[LXBSG] = IJBOz;
	}
	retVal.append((char*)cP2);
	return retVal;
}

string StringEncryption::getLegacyMenu()
{
	string retVal = getLegacy();
	// part2 = "Menu.x"
	unsigned char part2[7] = { 0xB1, 0x9A, 0x92, 0x8C, 0xD4, 0x8B, 0x04 };
	for (unsigned int QFRwb = 0, uzlPi = 0; QFRwb < 7; QFRwb++)
	{
		uzlPi = part2[QFRwb];
		uzlPi = ~uzlPi;
		uzlPi--;
		uzlPi += QFRwb;
		part2[QFRwb] = uzlPi;
	}
	retVal.append((char*)part2);
	// part3 = "ex"
	unsigned char part3[3] = { 0x9A, 0x89, 0x03 };
	for (unsigned int bLnhB = 0, LvwDj = 0; bLnhB < 3; bLnhB++)
	{
		LvwDj = part3[bLnhB];
		LvwDj -= bLnhB;
		LvwDj = ~LvwDj;
		LvwDj += bLnhB;
		part3[bLnhB] = LvwDj;
	}
	retVal.append((char*)part3);
	return retVal;
}

string StringEncryption::getHdd()
{
	string retVal;
	// part1 = "HDD:\\"
	unsigned char part1[6] = { 0x21, 0x14, 0x17, 0xF1, 0x7D, 0x0F };
	for (unsigned int hyoim = 0, OHzDk = 0; hyoim < 6; hyoim++)
	{
		OHzDk = part1[hyoim];
		OHzDk += hyoim;
		OHzDk = (((OHzDk & 0xFF) >> 2) | (OHzDk << 6)) & 0xFF;
		OHzDk -= hyoim;
		part1[hyoim] = OHzDk;
	}
	retVal.append((char*)part1);
	return retVal;
}

string StringEncryption::getFullHddPath()
{
	//returns \\Device\\Harddisk0\\Partition1
	// \\Devi + ce\\Ha + rddisk + 0\\Par + tition + 1
	string retVal;

	// path1 = "\\Devi"
	unsigned char path1[6] = { 0x8D, 0xED, 0x69, 0x25, 0x59, 0xFE };
	for (unsigned int sSuZQ = 0, sMwgm = 0; sSuZQ < 6; sSuZQ++)
	{
		sMwgm = path1[sSuZQ];
		sMwgm = ~sMwgm;
		sMwgm--;
		sMwgm = (((sMwgm & 0xFF) >> 2) | (sMwgm << 6)) & 0xFF;
		path1[sSuZQ] = sMwgm;
	}
	retVal.append((char*)path1);
	// path2 = "ce\\Ha"
	unsigned char path2[6] = { 0x9D, 0x9C, 0xA6, 0xBB, 0xA3, 0x05 };
	for (unsigned int KCVQo = 0, NlYXu = 0; KCVQo < 6; KCVQo++)
	{
		NlYXu = path2[KCVQo];
		NlYXu = ~NlYXu;
		NlYXu++;
		NlYXu += KCVQo;
		path2[KCVQo] = NlYXu;
	}
	retVal.append((char*)path2);
	// path3 = "rddisk"
	unsigned char path3[7] = { 0x63, 0xA6, 0x66, 0x65, 0x22, 0x64, 0x7E };
	for (unsigned int GVNUb = 0, FAQWO = 0; GVNUb < 7; GVNUb++)
	{
		FAQWO = path3[GVNUb];
		FAQWO = ((FAQWO << 2) | ((FAQWO & 0xFF) >> 6)) & 0xFF;
		FAQWO ^= GVNUb;
		FAQWO = ~FAQWO;
		path3[GVNUb] = FAQWO;
	}
	retVal.append((char*)path3);
	// path4 = "0\\Par"
	unsigned char path4[6] = { 0x2F, 0x5B, 0x4F, 0x5E, 0x71, 0xFF };
	for (unsigned int WqxLR = 0, iMrfO = 0; WqxLR < 6; WqxLR++)
	{
		iMrfO = path4[WqxLR];
		iMrfO += WqxLR;
		iMrfO++;
		iMrfO ^= WqxLR;
		path4[WqxLR] = iMrfO;
	}
	retVal.append((char*)path4);
	// path5 = "tition1"
	unsigned char path5[8] = { 0x6F, 0x0E, 0x6F, 0x0E, 0xCE, 0xAE, 49, 0x00 };
	for (unsigned int WSGqH = 0, kDTfx = 0; WSGqH < 6; WSGqH++)
	{
		kDTfx = path5[WSGqH];
		kDTfx--;
		kDTfx = ((kDTfx << 3) | ((kDTfx & 0xFF) >> 5)) & 0xFF;
		kDTfx++;
		path5[WSGqH] = kDTfx;
	}
	retVal.append((char*)path5);
	return retVal;
}

string StringEncryption::getLegacyMenuPath()
{
	//returns HDD:\\LegacyMenu.xex
	return getHdd() + getLegacyMenu();
}

string StringEncryption::getLegacyFolder()
{
	//returns HDD:\\Legacy
	return getHdd() + getLegacy();
}

string StringEncryption::getPatchPath()
{
	//returns HDD:\\Legacy\\patch
	string retVal = getLegacyFolder();

	// cP3 = "\\patc"
	unsigned char cP3[7] = { 0xD0, 0xC6, 0x4E, 0xC4, 0x4D, 
		104, 0 };//added 'h' and null terminator
	for (unsigned int tWygs = 0, pAOCd = 0; tWygs < 5; tWygs++)
	{
		pAOCd = cP3[tWygs];
		pAOCd++;
		pAOCd = ((pAOCd << 1) | ((pAOCd & 0xFF) >> 7)) & 0xFF;
		pAOCd = ~pAOCd;
		cP3[tWygs] = pAOCd;
	}
	retVal.append((char*)cP3);
	return retVal;
}
string StringEncryption::getSymbLinkPrefix(BOOL system)
{
	//returns "\\System??\\%s" if system is true, "\\??\\%s" otherwise
	string retVal;
	// p1 = "\\"
	unsigned char p1[2] = { 0x54, 0xB1 };
	for (unsigned int mjSeV = 0, cyonH = 0; mjSeV < 2; mjSeV++)
	{
		cyonH = p1[mjSeV];
		cyonH -= mjSeV;
		cyonH += 0x4F;
		cyonH = ~cyonH;
		p1[mjSeV] = cyonH;
	}
	retVal.append((char*)p1);
	if (system)
	{
		// system = "System"
		unsigned char system[7] = { 0x52, 0x76, 0x6E, 0x73, 0x5C, 0x62, 0xFF };
		for (unsigned int OlZIn = 0, vGmlk = 0; OlZIn < 7; OlZIn++)
		{
			vGmlk = system[OlZIn];
			vGmlk += OlZIn;
			vGmlk++;
			vGmlk ^= OlZIn;
			system[OlZIn] = vGmlk;
		}
		retVal.append((char*)system);
	}
	// p2 = "??\\%s"
	unsigned char p2[6] = { 0xE0, 0xE0, 0x03, 0xEA, 0x1C, 0xCF };
	for (unsigned int kIFdQ = 0, FUxhs = 0; kIFdQ < 6; kIFdQ++)
	{
		FUxhs = p2[kIFdQ];
		FUxhs = ~FUxhs;
		FUxhs += 0xB8;
		FUxhs ^= 0xE8;
		p2[kIFdQ] = FUxhs;
	}
	retVal.append((char*)p2);
	return retVal;
}
string StringEncryption::getAuthFilename()
{
	string retVal = getHdd();
	// s = "X0294g"
	unsigned char s[7] = { 0xB1, 0x62, 0x67, 0x76, 0x6D, 0xD4, 0x07 };
	for (unsigned int tVhrK = 0, OBSeH = 0; tVhrK < 7; tVhrK++)
	{
		OBSeH = s[tVhrK];
		OBSeH--;
		OBSeH -= tVhrK;
		OBSeH = ((OBSeH << 7) | ((OBSeH & 0xFF) >> 1)) & 0xFF;
		s[tVhrK] = OBSeH;
	}
	retVal.append((char*)s);
	return retVal;
}
#pragma endregion

#pragma region UNICODE Strings
#pragma region helper methods
wstring getLegacyW()
{
	//returns L"Legacy" as a wstring
	wstring a;
	// p1 = "Legacy"
	wchar_t p1[7] = { 0xFFB3, 0xFF9A, 0xFF98, 0xFF9E, 0xFF9C, 0xFF86, 0xFFFF };
	for (unsigned int gGDyR = 0, AtxaX = 0; gGDyR < 7; gGDyR++)
	{
		AtxaX = p1[gGDyR];
		AtxaX += gGDyR;
		AtxaX = ~AtxaX;
		AtxaX += gGDyR;
		p1[gGDyR] = AtxaX;
	}
	a.append(p1);
	return a;
}
wstring getCouldntW()
{
	//returns L"Couldn't " as a wstring
	//since I use it multiple times
	wstring a;
	// p1 = "Couldn"
	wchar_t p1[7] = { 0x7FDE, 0xFFC8, 0x7FC4, 0x7FC8, 0xFFCF, 0x7FCA, 0xFFFC };
	for (unsigned int FfNTH = 0, lfIcd = 0; FfNTH < 7; FfNTH++)
	{
		lfIcd = p1[FfNTH];
		lfIcd = ~lfIcd;
		lfIcd = (((lfIcd & 0xFFFF) >> 15) | (lfIcd << 1)) & 0xFFFF;
		lfIcd ^= FfNTH;
		p1[FfNTH] = lfIcd;
	}
	a.append(p1);
	// p2 = "\'t "
	wchar_t p2[4] = { 0x4E00, 0xE7C0, 0x3F80, 0xFF7F };
	for (unsigned int QsoFS = 0, LiIWo = 0; QsoFS < 4; QsoFS++)
	{
		LiIWo = p2[QsoFS];
		LiIWo = (((LiIWo & 0xFFFF) >> 6) | (LiIWo << 10)) & 0xFFFF;
		LiIWo += QsoFS;
		LiIWo = (((LiIWo & 0xFFFF) >> 3) | (LiIWo << 13)) & 0xFFFF;
		p2[QsoFS] = LiIWo;
	}
	a.append(p2);
	return a;
}
#pragma endregion

PWCHAR StringEncryption::getPatchRecNotify()
{
	//L"Receiving Legacy patch. Please wait"
	wstring retVal;
	// p1 = "Receiv"
	wchar_t p1[7] = { 0xEA8E, 0xEA7C, 0xEA7F, 0xEA7E, 0xEA7B, 0xEA6F, 0xEAE6 };
	for (unsigned int HCZqU = 0, BWMES = 0; HCZqU < 7; HCZqU++)
	{
		BWMES = p1[HCZqU];
		BWMES -= HCZqU;
		BWMES = ~BWMES;
		BWMES += 0xEAE1;
		p1[HCZqU] = BWMES;
	}
	retVal.append(p1);
	// p2 = "ing Le"
	wchar_t p2[7] = { 0x006A, 0x0071, 0x0068, 0x0027, 0x0055, 0x006E, 0x0001 };
	for (unsigned int gdLIs = 0, vwWIa = 0; gdLIs < 7; gdLIs++)
	{
		vwWIa = p2[gdLIs];
		vwWIa ^= gdLIs;
		vwWIa--;
		vwWIa -= gdLIs;
		p2[gdLIs] = vwWIa;
	}
	retVal.append(p2);
	// p3 = "gacy p"
	wchar_t p3[7] = { 0xD80D, 0x080E, 0x380E, 0x480D, 0x0030, 0x800D, 0x0031 };
	for (unsigned int SJWoz = 0, zdeOP = 0; SJWoz < 7; SJWoz++)
	{
		zdeOP = p3[SJWoz];
		zdeOP = (((zdeOP & 0xFFFF) >> 11) | (zdeOP << 5)) & 0xFFFF;
		zdeOP ^= 0xF5FA;
		zdeOP += 0x0C26;
		p3[SJWoz] = zdeOP;
	}
	retVal.append(p3);
	// p4 = "atch. "
	wchar_t p4[7] = { 0xF9EF, 0xF8BE, 0xF9CD, 0xF97C, 0xFD1B, 0xFDFA, 0xFFF9 };
	for (unsigned int iwfyj = 0, axNmf = 0; iwfyj < 7; iwfyj++)
	{
		axNmf = p4[iwfyj];
		axNmf = ~axNmf;
		axNmf -= iwfyj;
		axNmf = ((axNmf << 12) | ((axNmf & 0xFFFF) >> 4)) & 0xFFFF;
		p4[iwfyj] = axNmf;
	}
	retVal.append(p4);
	// p5 = "Please"
	wchar_t p5[7] = { 0xEB1F, 0xEB3D, 0xEB34, 0xEB30, 0xEB42, 0xEB3C, 0xEAD3 };
	for (unsigned int MlCRd = 0, cFgCb = 0; MlCRd < 7; MlCRd++)
	{
		cFgCb = p5[MlCRd];
		cFgCb ^= MlCRd;
		cFgCb -= MlCRd;
		cFgCb -= 0xEACF;
		p5[MlCRd] = cFgCb;
	}
	retVal.append(p5);
	// p6 = " wait"
	wchar_t p6[6] = { 0x45F4, 0x45AC, 0x45B5, 0x45BC, 0x459C, 0x45CF };
	for (unsigned int EBMXW = 0, rBWzd = 0; EBMXW < 6; EBMXW++)
	{
		rBWzd = p6[EBMXW];
		rBWzd += EBMXW;
		rBWzd ^= 0x45D5;
		rBWzd--;
		p6[EBMXW] = rBWzd;
	}
	retVal.append(p6);
	PWCHAR temp = new WCHAR[retVal.length()];
	return lstrcpyW(temp, retVal.c_str());
}

PWCHAR StringEncryption::getPatchSuccessNotify()
{
	//L"Legacy patch downloaded & ready, you can start GTA now"
	wstring retVal = getLegacyW();
	// p1 = " patch"
	wchar_t p1[7] = { 0xD083, 0xD034, 0xD044, 0xD032, 0xD044, 0xD040, 0xD0A9 };
	for (unsigned int DJlxS = 0, GmRbo = 0; DJlxS < 7; DJlxS++)
	{
		GmRbo = p1[DJlxS];
		GmRbo -= DJlxS;
		GmRbo = ~GmRbo;
		GmRbo += 0xD0A4;
		p1[DJlxS] = GmRbo;
	}
	retVal.append(p1);
	// p2 = " downl"
	wchar_t p2[7] = { 0x1BF0, 0x1BAD, 0x1BA3, 0x1B9C, 0x1BA6, 0x1BA9, 0x1C16 };
	for (unsigned int SPXCa = 0, dgZGf = 0; SPXCa < 7; SPXCa++)
	{
		dgZGf = p2[SPXCa];
		dgZGf += 0xE3EF;
		dgZGf = ~dgZGf;
		dgZGf += SPXCa;
		p2[SPXCa] = dgZGf;
	}
	retVal.append(p2);
	// p3 = "oaded "
	wchar_t p3[7] = { 0xE55A, 0xE0DA, 0xE39A, 0xE3DA, 0xE39A, 0xD09A, 0xD89A };
	for (unsigned int eATFa = 0, YXVxJ = 0; eATFa < 7; eATFa++)
	{
		YXVxJ = p3[eATFa];
		YXVxJ ^= 0x8992;
		YXVxJ = (((YXVxJ & 0xFFFF) >> 6) | (YXVxJ << 10)) & 0xFFFF;
		YXVxJ -= 0x2144;
		p3[eATFa] = YXVxJ;
	}
	retVal.append(p3);
	// p4 = "& read"
	wchar_t p4[7] = { 0x0027, 0x0023, 0x0073, 0x0064, 0x0062, 0x0067, 0x0001 };
	for (unsigned int gIkKc = 0, XwhWC = 0; gIkKc < 7; gIkKc++)
	{
		XwhWC = p4[gIkKc];
		XwhWC ^= gIkKc;
		XwhWC--;
		XwhWC ^= gIkKc;
		p4[gIkKc] = XwhWC;
	}
	retVal.append(p4);
	// p5 = "y, you"
	wchar_t p5[7] = { 0x10B8, 0x1106, 0x1113, 0x10BB, 0x10C6, 0x10C1, 0x1137 };
	for (unsigned int RfDWF = 0, ABZvO = 0; RfDWF < 7; RfDWF++)
	{
		ABZvO = p5[RfDWF];
		ABZvO -= RfDWF;
		ABZvO += 0xEECE;
		ABZvO = ~ABZvO;
		p5[RfDWF] = ABZvO;
	}
	retVal.append(p5);
	// p6 = " can s"
	wchar_t p6[7] = { 0x0080, 0x0189, 0x018E, 0x01B7, 0x0094, 0x01DD, 0x001E };
	for (unsigned int hNHYo = 0, HUWDX = 0; hNHYo < 7; hNHYo++)
	{
		HUWDX = p6[hNHYo];
		HUWDX ^= hNHYo;
		HUWDX = (((HUWDX & 0xFFFF) >> 2) | (HUWDX << 14)) & 0xFFFF;
		HUWDX ^= hNHYo;
		p6[hNHYo] = HUWDX;
	}
	retVal.append(p6);
	// p7 = "tart G"
	wchar_t p7[7] = { 0xE7AB, 0xE7B9, 0xE7AF, 0xE7A4, 0xE7FB, 0xE797, 0xE7D5 };
	for (unsigned int wQCHY = 0, MuqBG = 0; wQCHY < 7; wQCHY++)
	{
		MuqBG = p7[wQCHY];
		MuqBG ^= 0xDCE2;
		MuqBG += wQCHY;
		MuqBG ^= 0x3B3D;
		p7[wQCHY] = MuqBG;
	}
	retVal.append(p7);
	// p8 = "TA now"
	wchar_t p8[7] = { 0x0AA0, 0x0820, 0x0460, 0x0DC0, 0x0D80, 0x0E60, 0x00E0 };
	for (unsigned int asLZy = 0, yEbNB = 0; asLZy < 7; asLZy++)
	{
		yEbNB = p8[asLZy];
		yEbNB = ((yEbNB << 11) | ((yEbNB & 0xFFFF) >> 5)) & 0xFFFF;
		yEbNB--;
		yEbNB ^= asLZy;
		p8[asLZy] = yEbNB;
	}
	retVal.append(p8);
	PWCHAR temp = new WCHAR[retVal.length()];
	return lstrcpyW(temp, retVal.c_str());
}

wstring StringEncryption::getErrorStr()
{
	wstring retVal;
	// encrypted with https://www.stringencrypt.com (v1.1.0) [C/C++]
	// err = "Error "
	wchar_t err[7] = { 0x08B8, 0xA8BD, 0xA8BC, 0x48BA, 0xA8BA, 0x68AF, 0x68AA };
	for (unsigned int DLGqa = 0, GBuTY = 0; DLGqa < 7; DLGqa++)
	{
		GBuTY = err[DLGqa];
		GBuTY -= 0x68B0;
		GBuTY += DLGqa;
		GBuTY = ((GBuTY << 3) | ((GBuTY & 0xFFFF) >> 13)) & 0xFFFF;
		err[DLGqa] = GBuTY;
	}
	retVal.append(err);
	return retVal;
}

PWCHAR StringEncryption::getErrorNumStr(int num)
{
	//used for the several Error notifies when loading the menu
	//Ex: L"Error 1" used for the notify if xexloadimage fails
	wstring retVal = getErrorStr();
	retVal.append(to_wstring((long long)num));
	PWCHAR temp = new WCHAR[retVal.length() + 1];
	lstrcpyW(temp, retVal.c_str());
	return temp;
}

PWCHAR StringEncryption::getDigestErrorStr()
{
	//L"Couldn't get module digest"
	wstring retVal = getCouldntW();
	// p1 = "get mo"
	wchar_t p1[7] = { 0xC019, 0xC018, 0x001D, 0x0008, 0x4019, 0x4019, 0x0000 };
	for (unsigned int KXMDP = 0, dZfHO = 0; KXMDP < 7; KXMDP++)
	{
		dZfHO = p1[KXMDP];
		dZfHO = (((dZfHO & 0xFFFF) >> 14) | (dZfHO << 2)) & 0xFFFF;
		dZfHO += KXMDP;
		dZfHO ^= KXMDP;
		p1[KXMDP] = dZfHO;
	}
	retVal.append(p1);
	// p2 = "dule d"
	wchar_t p2[7] = { 0x6E0F, 0x6E1F, 0x6E15, 0x6E0D, 0x6DCF, 0x6E0A, 0x6DED };
	for (unsigned int MqwTt = 0, IjEpX = 0; MqwTt < 7; MqwTt++)
	{
		IjEpX = p2[MqwTt];
		IjEpX += 0x8B38;
		IjEpX ^= MqwTt;
		IjEpX ^= 0xF923;
		p2[MqwTt] = IjEpX;
	}
	retVal.append(p2);
	// p3 = "igest"
	wchar_t p3[6] = { 0x006A, 0x006A, 0x006A, 0x007A, 0x007D, 0x000B };
	for (unsigned int Egtev = 0, pFdEv = 0; Egtev < 6; Egtev++)
	{
		pFdEv = p3[Egtev];
		pFdEv -= Egtev;
		pFdEv--;
		pFdEv -= Egtev;
		p3[Egtev] = pFdEv;
	}
	retVal.append(p3);
	PWCHAR temp = new WCHAR[retVal.length() + 1];
	lstrcpyW(temp, retVal.c_str());
	return temp;
}

PWCHAR StringEncryption::getUpdError()
{
	//L"Couldn't receive update!"
	wstring retVal = getCouldntW();
	// p1 = "receiv"
	wchar_t p1[7] = { 0x7C92, 0xBC95, 0x3C96, 0xBC95, 0xBC94, 0x7C91, 0xFCAE };
	for (unsigned int jWiKl = 0, xJjWA = 0; jWiKl < 7; jWiKl++)
	{
		xJjWA = p1[jWiKl];
		xJjWA = ~xJjWA;
		xJjWA += 0xFCAF;
		xJjWA = ((xJjWA << 2) | ((xJjWA & 0xFFFF) >> 14)) & 0xFFFF;
		p1[jWiKl] = xJjWA;
	}
	retVal.append(p1);
	// p2 = "e upda"
	wchar_t p2[7] = { 0xF8EC, 0xF862, 0xF90C, 0xF902, 0xF8EA, 0xF8E4, 0xF823 };
	for (unsigned int SIGsW = 0, cPeBM = 0; SIGsW < 7; SIGsW++)
	{
		cPeBM = p2[SIGsW];
		cPeBM -= 0xF824;
		cPeBM = (((cPeBM & 0xFFFF) >> 1) | (cPeBM << 15)) & 0xFFFF;
		cPeBM++;
		p2[SIGsW] = cPeBM;
	}
	retVal.append(p2);
	// p3 = "te!"
	wchar_t p3[4] = { 0x72DF, 0x7266, 0x7045, 0x6F3C };
	for (unsigned int huzIA = 0, YoCuq = 0; huzIA < 4; huzIA++)
	{
		YoCuq = p3[huzIA];
		YoCuq += 0x90C1;
		YoCuq += huzIA;
		YoCuq = ((YoCuq << 13) | ((YoCuq & 0xFFFF) >> 3)) & 0xFFFF;
		p3[huzIA] = YoCuq;
	}
	retVal.append(p3);
	PWCHAR temp = new WCHAR[retVal.length() + 1];
	lstrcpyW(temp, retVal.c_str());
	return temp;
}

PWCHAR StringEncryption::getUpdWriteError()
{
	//L"Couldn't write update to xex"
	wstring retVal = getCouldntW();
	// p1 = "write "
	wchar_t p1[7] = { 0xF9CF, 0xF9D3, 0xF9DB, 0xF9CF, 0xF9DD, 0xFA21, 0xFA40 };
	for (unsigned int jUnZe = 0, pbglo = 0; jUnZe < 7; jUnZe++)
	{
		pbglo = p1[jUnZe];
		pbglo += 0x05B9;
		pbglo += jUnZe;
		pbglo = ~pbglo;
		p1[jUnZe] = pbglo;
	}
	retVal.append(p1);
	// p2 = "update"
	wchar_t p2[7] = { 0x2097, 0x20BF, 0x211F, 0x2137, 0x209F, 0x2117, 0x243F };
	for (unsigned int TjzEL = 0, jfWcY = 0; TjzEL < 7; TjzEL++)
	{
		jfWcY = p2[TjzEL];
		jfWcY += 0xDBC0;
		jfWcY = (((jfWcY & 0xFFFF) >> 3) | (jfWcY << 13)) & 0xFFFF;
		jfWcY = ~jfWcY;
		p2[TjzEL] = jfWcY;
	}
	retVal.append(p2);
	// p3 = " to xe"
	wchar_t p3[7] = { 0xFFDE, 0xFF89, 0xFF8D, 0xFFDB, 0xFF82, 0xFF94, 0xFFF8 };
	for (unsigned int HsoYp = 0, sgkzd = 0; HsoYp < 7; HsoYp++)
	{
		sgkzd = p3[HsoYp];
		sgkzd++;
		sgkzd += HsoYp;
		sgkzd = ~sgkzd;
		p3[HsoYp] = sgkzd;
	}
	retVal.append(p3);
	// p4 = "x"
	wchar_t p4[2] = { 0x979C, 0x9813 };
	for (unsigned int hAsGd = 0, veCYZ = 0; hAsGd < 2; hAsGd++)
	{
		veCYZ = p4[hAsGd];
		veCYZ = ~veCYZ;
		veCYZ += 0x9815;
		veCYZ -= hAsGd;
		p4[hAsGd] = veCYZ;
	}
	retVal.append(p4);
	PWCHAR temp = new WCHAR[retVal.length() + 1];
	lstrcpyW(temp, retVal.c_str());
	return temp;
}

PWCHAR StringEncryption::getUpdCmpl()
{
	//L"Legacy Menu - Update Complete. Rebooting Now..."
	wstring retVal = getLegacyW();
	// p1 = " Menu "
	wchar_t p1[7] = { 0xAA30, 0x0231, 0x3831, 0x4431, 0x4C31, 0xB430, 0x7630 };
	for (unsigned int JySjX = 0, XGrhj = 0; JySjX < 7; JySjX++)
	{
		XGrhj = p1[JySjX];
		XGrhj = ((XGrhj << 7) | ((XGrhj & 0xFFFF) >> 9)) & 0xFFFF;
		XGrhj -= 0x1835;
		XGrhj ^= JySjX;
		p1[JySjX] = XGrhj;
	}
	retVal.append(p1);
	// p2 = "- Upda"
	wchar_t p2[7] = { 0x002C, 0x001D, 0x0050, 0x0069, 0x005B, 0x0056, 0xFFF3 };
	for (unsigned int HdnPx = 0, rNuKM = 0; HdnPx < 7; HdnPx++)
	{
		rNuKM = p2[HdnPx];
		rNuKM += HdnPx;
		rNuKM++;
		rNuKM += HdnPx;
		p2[HdnPx] = rNuKM;
	}
	retVal.append(p2);
	// p3 = "te Com"
	wchar_t p3[7] = { 0x0074, 0x0064, 0x0022, 0x0040, 0x006B, 0x0068, 0x0006 };
	for (unsigned int oZIcO = 0, AYIdE = 0; oZIcO < 7; oZIcO++)
	{
		AYIdE = p3[oZIcO];
		AYIdE = ~AYIdE;
		AYIdE ^= oZIcO;
		AYIdE = ~AYIdE;
		p3[oZIcO] = AYIdE;
	}
	retVal.append(p3);
	// p4 = "plete."
	wchar_t p4[7] = { 0x00C0, 0x00B8, 0x00AA, 0x00C8, 0x00AA, 0x003C, 0xFFE1 };
	for (unsigned int thexO = 0, LuBJA = 0; thexO < 7; thexO++)
	{
		LuBJA = p4[thexO];
		LuBJA += 0x001E;
		LuBJA = ((LuBJA << 15) | ((LuBJA & 0xFFFF) >> 1)) & 0xFFFF;
		LuBJA++;
		p4[thexO] = LuBJA;
	}
	retVal.append(p4);
	// p5 = " Reboo"
	wchar_t p5[7] = { 0x0021, 0x0055, 0x006A, 0x0065, 0x0070, 0x0070, 0x000D };
	for (unsigned int ZCiQq = 0, gFesp = 0; ZCiQq < 7; ZCiQq++)
	{
		gFesp = p5[ZCiQq];
		gFesp--;
		gFesp -= ZCiQq;
		gFesp ^= ZCiQq;
		p5[ZCiQq] = gFesp;
	}
	retVal.append(p5);
	// p6 = "ting N"
	wchar_t p6[7] = { 0xFF8C, 0xFF96, 0xFF90, 0xFF96, 0xFFDC, 0xFFAD, 0xFFFA };
	for (unsigned int oRjNL = 0, iNhvM = 0; oRjNL < 7; oRjNL++)
	{
		iNhvM = p6[oRjNL];
		iNhvM = ~iNhvM;
		iNhvM -= oRjNL;
		iNhvM++;
		p6[oRjNL] = iNhvM;
	}
	retVal.append(p6);
	// p7 = "ow..."
	wchar_t p7[6] = { 0x28BA, 0xA8BB, 0x18BE, 0x18BE, 0x18BE, 0xF8BC };
	for (unsigned int XyBMY = 0, nhiPY = 0; XyBMY < 6; XyBMY++)
	{
		nhiPY = p7[XyBMY];
		nhiPY += 0x7160;
		nhiPY = (((nhiPY & 0xFFFF) >> 12) | (nhiPY << 4)) & 0xFFFF;
		nhiPY ^= 0xA1C6;
		p7[XyBMY] = nhiPY;
	}
	retVal.append(p7);
	PWCHAR temp = new WCHAR[retVal.length() + 1];
	lstrcpyW(temp, retVal.c_str());
	return temp;
}

PWCHAR StringEncryption::getGamesaveErr()
{
	//L"Couldn't write gamesave to console!"
	wstring retVal = getCouldntW();
	// p1 = "write "
	wchar_t p1[7] = { 0xFF88, 0xFF8D, 0xFF96, 0xFF8B, 0xFF9A, 0xFFDF, 0xFFFF };
	for (unsigned int JADrd = 0, hGRCc = 0; JADrd < 7; JADrd++)
	{
		hGRCc = p1[JADrd];
		hGRCc += JADrd;
		hGRCc = ~hGRCc;
		hGRCc += JADrd;
		p1[JADrd] = hGRCc;
	}
	retVal.append(p1);
	// p2 = "gamesa"
	wchar_t p2[7] = { 0x6219, 0x5B19, 0x6A19, 0x6119, 0x7219, 0x5F19, 0x0119 };
	for (unsigned int kefYl = 0, kqWze = 0; kefYl < 7; kefYl++)
	{
		kqWze = p2[kefYl];
		kqWze = (((kqWze & 0xFFFF) >> 8) | (kqWze << 8)) & 0xFFFF;
		kqWze -= 0x18FB;
		kqWze ^= kefYl;
		p2[kefYl] = kqWze;
	}
	retVal.append(p2);
	// p3 = "ve to "
	wchar_t p3[7] = { 0x0074, 0x0062, 0x001C, 0x006F, 0x0069, 0x0019, 0xFFF8 };
	for (unsigned int DUJZR = 0, rOHjZ = 0; DUJZR < 7; DUJZR++)
	{
		rOHjZ = p3[DUJZR];
		rOHjZ++;
		rOHjZ += DUJZR;
		rOHjZ++;
		p3[DUJZR] = rOHjZ;
	}
	retVal.append(p3);
	// p4 = "consol"
	wchar_t p4[7] = { 0x96BE, 0x96B2, 0x96B3, 0x96AE, 0x96B2, 0x96B5, 0x9621 };
	for (unsigned int tnOzQ = 0, EBHDW = 0; tnOzQ < 7; tnOzQ++)
	{
		EBHDW = p4[tnOzQ];
		EBHDW ^= 0xC2E0;
		EBHDW -= 0x54C2;
		EBHDW = ~EBHDW;
		p4[tnOzQ] = EBHDW;
	}
	retVal.append(p4);
	// p5 = "e!"
	wchar_t p5[3] = { 0x0065, 0x0020, 0xFFFA };
	for (unsigned int KgCkY = 0, lDMcL = 0; KgCkY < 3; KgCkY++)
	{
		lDMcL = p5[KgCkY];
		lDMcL += KgCkY;
		lDMcL ^= KgCkY;
		lDMcL += KgCkY;
		p5[KgCkY] = lDMcL;
	}
	retVal.append(p5);
	PWCHAR temp = new WCHAR[retVal.length() + 1];
	lstrcpyW(temp, retVal.c_str());
	return temp;
}

PWCHAR StringEncryption::getGamesaveWrite()
{
	//L"Wrote gamesave to console"
	wstring retVal;
	// p1 = "Wrote "
	wchar_t p1[7] = { 0x3FF5, 0xDFF1, 0x3FF2, 0x9FF1, 0x7FF3, 0x1FFC, 0x0000 };
	for (unsigned int DKrCa = 0, QmqdN = 0; DKrCa < 7; DKrCa++)
	{
		QmqdN = p1[DKrCa];
		QmqdN = (((QmqdN & 0xFFFF) >> 13) | (QmqdN << 3)) & 0xFFFF;
		QmqdN = ~QmqdN;
		QmqdN++;
		p1[DKrCa] = QmqdN;
	}
	retVal.append(p1);
	// p2 = "gamesa"
	wchar_t p2[7] = { 0x6219, 0x5B19, 0x6A19, 0x6119, 0x7219, 0x5F19, 0x0119 };
	for (unsigned int kefYl = 0, kqWze = 0; kefYl < 7; kefYl++)
	{
		kqWze = p2[kefYl];
		kqWze = (((kqWze & 0xFFFF) >> 8) | (kqWze << 8)) & 0xFFFF;
		kqWze -= 0x18FB;
		kqWze ^= kefYl;
		p2[kefYl] = kqWze;
	}
	retVal.append(p2);
	// p3 = "ve to "
	wchar_t p3[7] = { 0x0074, 0x0062, 0x001C, 0x006F, 0x0069, 0x0019, 0xFFF8 };
	for (unsigned int DUJZR = 0, rOHjZ = 0; DUJZR < 7; DUJZR++)
	{
		rOHjZ = p3[DUJZR];
		rOHjZ++;
		rOHjZ += DUJZR;
		rOHjZ++;
		p3[DUJZR] = rOHjZ;
	}
	retVal.append(p3);
	// p4 = "consol"
	wchar_t p4[7] = { 0x96BE, 0x96B2, 0x96B3, 0x96AE, 0x96B2, 0x96B5, 0x9621 };
	for (unsigned int tnOzQ = 0, EBHDW = 0; tnOzQ < 7; tnOzQ++)
	{
		EBHDW = p4[tnOzQ];
		EBHDW ^= 0xC2E0;
		EBHDW -= 0x54C2;
		EBHDW = ~EBHDW;
		p4[tnOzQ] = EBHDW;
	}
	retVal.append(p4);
	// p5 = "e"
	wchar_t p5[2] = { 0x00CC, 0x0000 };
	for (unsigned int lHvdj = 0, JTSoz = 0; lHvdj < 2; lHvdj++)
	{
		JTSoz = p5[lHvdj];
		JTSoz = (((JTSoz & 0xFFFF) >> 1) | (JTSoz << 15)) & 0xFFFF;
		JTSoz--;
		JTSoz += lHvdj;
		p5[lHvdj] = JTSoz;
	}
	retVal.append(p5);
	PWCHAR temp = new WCHAR[retVal.length() + 1];
	lstrcpyW(temp, retVal.c_str());
	return temp;
}

PWCHAR StringEncryption::getGamesaveRecErr()
{
	//L"Couldn't receive gamesave"
	wstring retVal = getCouldntW();
	// p1 = "receiv"
	wchar_t p1[7] = { 0xEA15, 0xEA2F, 0xEA33, 0xEA2F, 0xEA27, 0xEA0D, 0xEAF9 };
	for (unsigned int ksMEV = 0, DHPtr = 0; ksMEV < 7; ksMEV++)
	{
		DHPtr = p1[ksMEV];
		DHPtr = ((DHPtr << 15) | ((DHPtr & 0xFFFF) >> 1)) & 0xFFFF;
		DHPtr = ~DHPtr;
		DHPtr -= 0x0A83;
		p1[ksMEV] = DHPtr;
	}
	retVal.append(p1);
	// p2 = "e game"
	wchar_t p2[7] = { 0x7CDC, 0xFCFF, 0x7CDF, 0x7CDD, 0x7CDC, 0x7CD9, 0xFCE8 };
	for (unsigned int PfIzK = 0, DEQGx = 0; PfIzK < 7; PfIzK++)
	{
		DEQGx = p2[PfIzK];
		DEQGx ^= PfIzK;
		DEQGx = ((DEQGx << 1) | ((DEQGx & 0xFFFF) >> 15)) & 0xFFFF;
		DEQGx ^= 0xF9DD;
		p2[PfIzK] = DEQGx;
	}
	retVal.append(p2);
	// p3 = "save"
	wchar_t p3[5] = { 0x0071, 0x0060, 0x0076, 0x0066, 0xFFFA };
	for (unsigned int tTOhq = 0, YPVIw = 0; tTOhq < 5; tTOhq++)
	{
		YPVIw = p3[tTOhq];
		YPVIw++;
		YPVIw ^= tTOhq;
		YPVIw++;
		p3[tTOhq] = YPVIw;
	}
	retVal.append(p3);
	PWCHAR temp = new WCHAR[retVal.length() + 1];
	lstrcpyW(temp, retVal.c_str());
	return temp;
}
#pragma endregion