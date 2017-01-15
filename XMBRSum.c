///////////////////////////////////////////////////////////////////////////////
// X-Tension API - template for new X-Tensions
// Adapted for C/C++ by Björn Ganster in 2012
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <wincrypt.h>
#include "X-Tension.h"

// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation

#include <wchar.h>

#define MAX_MSG_LEN 128

wchar_t* XT_NAME = L"[MBRCheck]";

BOOL APIENTRY DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}

///////////////////////////////////////////////////////////////////////////////
// MD5 Lookup

LPWSTR lookupMD5(LPWSTR calcd_md5)
{
	if (wcscmp(calcd_md5, L"5fb38429d5d77768867c76dcbdb35194") == 0)
	{
		return L"NULL_BYTES";
	}
	else if (wcscmp(calcd_md5, L"a36c5e4f47e84449ff07ed3517b43a31") == 0)
	{
		return L"Windows 7/8.1/10/2012R2";
	}
	else if (wcscmp(calcd_md5, L"8f558eb6672622401da993e1e865c861") == 0)
	{
		return L"Windows XPSP2";
	}
	else if(wcscmp(calcd_md5, L"017e003ab27b155b3a606eb18257fc5d") == 0)
	{
		return L"Linux Mint 17/18, SIFT3";
	}
	else if(wcscmp(calcd_md5, L"e93d266998c64f903d6e2758ca2f8efb") == 0)
	{
		return L"Kali Linux 1.1.0c";
	}
	else if(wcscmp(calcd_md5, L"b7310d12ff8857d5b67eaa63423edb33") == 0)
	{
		return L"TrueCrypt";
	}
	else
	{
		return L"UNKNOWN";
	}
}

///////////////////////////////////////////////////////////////////////////////
// XT_Init

LONG __stdcall XT_Init(CallerInfo info, DWORD nFlags, HANDLE hMainWnd, void* lpReserved)
{
	XT_RetrieveFunctionPointers();
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Prepare

LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void* lpReserved)
{
	wchar_t *buf = malloc(sizeof(wchar_t)*MAX_MSG_LEN);

	if (XT_ACTION_RUN != nOpType)
	{
		swprintf(buf, MAX_MSG_LEN, L"%ls This X-Tension should only be invoked via 'Tools' -> 'Run X-Tensions...' (Shift+F8)", XT_NAME);
		XWF_OutputMessage (buf, 0);
		return 0;
	}

	swprintf(buf, MAX_MSG_LEN, L"%ls Starting", XT_NAME);
	XWF_OutputMessage (buf, 0);

	HANDLE hEvObj = XWF_GetFirstEvObj(NULL);
	while(hEvObj != NULL)
	{
		LPWSTR pEvObjTitle = (LPWSTR)XWF_GetEvObjProp(hEvObj, 6, NULL);
		INT64 iFSID = XWF_GetEvObjProp(hEvObj, 19, NULL);
		
		if (-16 != iFSID) // -16 = Physical Disk
		{
			swprintf(buf, MAX_MSG_LEN, L"%ls %ls - ignored", XT_NAME, pEvObjTitle);
			XWF_OutputMessage (buf, 0);
			hEvObj = XWF_GetNextEvObj(hEvObj, NULL);
			continue;
		}
		
		HANDLE hDisk = XWF_OpenEvObj(hEvObj, 0);

		if (0 == hDisk) // 0 = Unsuccessful
		{
			swprintf(buf, MAX_MSG_LEN, L"%ls %ls - Failed to open evidence!", XT_NAME, pEvObjTitle);
			XWF_OutputMessage (buf, 0);
			hEvObj = XWF_GetNextEvObj(hEvObj, NULL);
			continue;
		}
		
		LPVOID lpBuffer = malloc(512);
		DWORD iBytesRead = XWF_Read(hDisk, 0, lpBuffer, 512);

		if (512 != iBytesRead)
		{
			swprintf(buf, MAX_MSG_LEN, L"%ls %ls - Only read %d bytes! Wanted 512!", XT_NAME, pEvObjTitle, iBytesRead);
			XWF_OutputMessage (buf, 0);
			hEvObj = XWF_GetNextEvObj(hEvObj, NULL);
			continue;
		}
		
		char *bytes = (char *)lpBuffer;
		if ((*(bytes+510) == (char)0x55) && (*(bytes+511) == (char)0xAA))
		{
			swprintf(buf, MAX_MSG_LEN, L"%ls %ls - Signature OK (55AA)",
				XT_NAME, pEvObjTitle);
			XWF_OutputMessage (buf, 0);
		}
		else
		{
			swprintf(buf, MAX_MSG_LEN, L"%ls %ls - Unexpected signature: %hhX%hhX!",
				XT_NAME, pEvObjTitle, *(bytes+510), *(bytes+511));
			XWF_OutputMessage (buf, 0);
		}

		// Calc MD5 of bytes 0-439
		HCRYPTPROV hProv = 0;
	    HCRYPTHASH hHash = 0;
	    BYTE rgbHash[16];
	    DWORD cbHash = 0;
	    CHAR rgbDigits[] = "0123456789abcdef";

	    // Get handle to the crypto provider
	    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	    {
			swprintf(buf, MAX_MSG_LEN, L"%ls %ls - Couldn't acquire crypto context!",
				XT_NAME, pEvObjTitle);
			XWF_OutputMessage (buf, 0);
			hEvObj = XWF_GetNextEvObj(hEvObj, NULL);
	        continue;
	    }

	    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	    {
			CryptReleaseContext(hProv, 0);
	        swprintf(buf, MAX_MSG_LEN, L"%ls %ls - Couldn't acquire crypto context!", XT_NAME, pEvObjTitle);
			XWF_OutputMessage (buf, 0);
			hEvObj = XWF_GetNextEvObj(hEvObj, NULL);
	        continue;
	    }

	    if (!CryptHashData(hHash, lpBuffer, 440, 0))
        {
            swprintf(buf, MAX_MSG_LEN, L"%ls %ls - CryptHashData failed!", XT_NAME, pEvObjTitle);
			XWF_OutputMessage (buf, 0);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
			hEvObj = XWF_GetNextEvObj(hEvObj, NULL);
			continue;
        }
	    
	    cbHash = 16;
	    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	    {
			LPWSTR md5 = malloc(sizeof(char)*32);
			for (DWORD i = 0; i < cbHash; i++)
	        {
	            swprintf(md5 + (i*2), 2, L"%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
	        }
			
			swprintf(buf, MAX_MSG_LEN, L"%ls %ls - %ls (%ls)", XT_NAME, pEvObjTitle, md5, lookupMD5(md5));
	        XWF_OutputMessage(buf, 0);
	    }
	    else
	    {
	        swprintf(buf, MAX_MSG_LEN, L"%ls %ls - CryptGetHashParam failed!", XT_NAME, pEvObjTitle);
			XWF_OutputMessage (buf, 0);
	    }

	    CryptDestroyHash(hHash);
	    CryptReleaseContext(hProv, 0);

		XWF_CloseEvObj(hEvObj);		

		hEvObj = XWF_GetNextEvObj(hEvObj, NULL);
	}

	swprintf(buf, MAX_MSG_LEN, L"%ls Done", XT_NAME);
	XWF_OutputMessage (buf, 0);

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Done

LONG __stdcall XT_Done(void* lpReserved)
{
	wchar_t *buf = malloc(sizeof(wchar_t)*MAX_MSG_LEN);
	swprintf(buf, MAX_MSG_LEN, L"%ls Done", XT_NAME);
	XWF_OutputMessage (buf, 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About

LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved)
{
	// XWF_OutputMessage (L"XT_New about", 0);
	return 0;
}
