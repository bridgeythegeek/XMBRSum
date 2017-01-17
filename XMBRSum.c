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

#include <stdio.h>
#include <wchar.h>

#define MAX_MSG_LEN 128

typedef struct good
{
	wchar_t md5[33];	// 32 + \0
	wchar_t desc[65];	// 64 + \0
	struct good *next;	// Next item in linked list
} good;

static wchar_t *XT_NAME = L"[XMBRSum]"; // Prefix for messages
wchar_t XT_PATH[MAX_PATH];
static good *the_goods = NULL; // Linked list

BOOL APIENTRY DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	GetModuleFileNameW(hInstDLL, XT_PATH, MAX_PATH); // Save the path of the DLL
    return TRUE;
}

///////////////////////////////////////////////////////////////////////////////
// MD5 Lookup
LPWSTR lookupMD5(LPWSTR calcd_md5)
{
	good *temp = the_goods;
	while(temp)
	{
		if (wcscmp(calcd_md5, temp->md5) == 0)
		{
			return temp->desc;
		}
		temp = temp->next;
	}

	return L"UNKNOWN";
}

///////////////////////////////////////////////////////////////////////////////
// Read the known good MD5 and their descriptions from a text file
int read_goods(void)
{
	wchar_t buf[MAX_MSG_LEN];

	// Get the path to the known goods file
	wchar_t* file = (wcsrchr(XT_PATH, '\\') + 1);
	int path_len = wcslen(XT_PATH);
	int file_len = wcslen(file);
	int good_path_len = path_len - file_len + 8 + 1; // good.txt + \0
	wchar_t good_path[good_path_len];
	memcpy(good_path, XT_PATH, sizeof(wchar_t) * (path_len - file_len));	
	memcpy(good_path + path_len - file_len, L"good.txt", sizeof(wchar_t) * 9);

	// Get file handle
	FILE* hFile = _wfopen(good_path, L"r");
	if (!hFile)
	{
		swprintf(buf, MAX_MSG_LEN, L"%ls Couldn't open '%ls' for reading!", XT_NAME, good_path);
		XWF_OutputMessage (buf, 0);
		return -1;
	}

	size_t line_length = sizeof(wchar_t) * 128;
	wchar_t *buffer = (wchar_t*)malloc(line_length);

	int count = 0;
	while(fgetws(buffer, line_length, hFile))
	{
		count++;

		if (buffer[32] != '\t')
		{
			swprintf(buf, MAX_MSG_LEN, L"%ls ERROR: Unexpected char at pos 32 on line %d. Line ignored. (Should be \\t)", XT_NAME, count);
			XWF_OutputMessage(buf, 0);
			continue;
		}

		if (buffer[wcslen(buffer)-1] != '\n')
		{
			swprintf(buf, MAX_MSG_LEN, L"%ls WARNING: Line %d has been truncated.", XT_NAME, count);
			XWF_OutputMessage(buf, 0);
		}
		
		good *g = (good *)malloc(sizeof(good));
		memcpy(g->md5, buffer, 32 * sizeof(wchar_t));
		g->md5[32] = '\0';
		memcpy(g->desc, buffer + 33, (wcslen(buffer) * sizeof(wchar_t)) - (33 * sizeof(wchar_t)));

		g->next = the_goods;

		the_goods = g;		
	}

	free(buffer);
	fclose(hFile);
	
	return count;
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
	wchar_t buf[MAX_MSG_LEN];

	if (XT_ACTION_RUN != nOpType)
	{
		swprintf(buf, MAX_MSG_LEN, L"%ls This X-Tension should only be invoked via 'Tools' -> 'Run X-Tensions...' (Shift+F8)", XT_NAME);
		XWF_OutputMessage (buf, 0);
		return 0;
	}

	swprintf(buf, MAX_MSG_LEN, L"%ls Reading known good MD5s.", XT_NAME);
	XWF_OutputMessage (buf, 0);
	int goods = read_goods();
	if (goods >= 0)
	{
		swprintf(buf, MAX_MSG_LEN, L"%ls Done, read %d known good MD5s.", XT_NAME, goods);
		XWF_OutputMessage (buf, 0);
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

	// free the linked-list
	while(the_goods)
	{
		good *temp = the_goods->next;
		free(the_goods);
		the_goods = temp;
	}

	swprintf(buf, MAX_MSG_LEN, L"%ls Done", XT_NAME);
	XWF_OutputMessage (buf, 0);

	return 1;
}
