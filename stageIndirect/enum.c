#include <windows.h>
#include <Psapi.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"
#include "typedef.h"
#include "Debug.h"



extern API_HASHING g_Api;

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess) {

	ULONG							uReturnLen1 = NULL,
		uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;

	


	// this will fail (with status = STATUS_INFO_LENGTH_MISMATCH), but that's ok, because we need to know how much to allocate (uReturnLen1)
	STATUS = NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);
	

	// allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
#ifdef DEBUG
		PRINTA("[HeapAlloc] failed, error: 0x%x\n", STATUS);
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("Allocated Buffer...\n");
#endif

	// since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// calling NtQuerySystemInformation with the right arguments, the output will be saved to 'SystemProcInfo'
	STATUS = NtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
		PRINTA("[!] NtQuerySystemInformation2 Failed With Error : 0x%x \n", STATUS);
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("Second NtQuery call ran...\n");
#endif

	while (TRUE) {

		// small check for the process's name size
		// comparing the enumerated process name to what we want to target
		if (SystemProcInfo->ImageName.Length && HASHW(SystemProcInfo->ImageName.Buffer) == HASHW(szProcName)) {
			// openning a handle to the target process and saving it, then breaking 
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
#ifdef DEBUG
			PRINTA("Running NtOpenProcess\n");
#endif
			break;
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// moving to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// freeing using the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// checking if we got the target's process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}