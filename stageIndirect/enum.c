#include <windows.h>
#include <Psapi.h>
#include <stdio.h>

#include "Common.h"


BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	DWORD		adwProcesses[1024 * 2],
		dwReturnLen1 = NULL,
		dwReturnLen2 = NULL,
		dwNmbrOfPids = NULL;

	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	// Get the array of pid's in the system
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array returned 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is NULL
		if (adwProcesses[i] != NULL) {

			// Opening a process handle 
			if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// if EnumProcessModules succeeded
					// get the name of 'hProcess', and saving it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Perform the comparison logic
						if (wcscmp(szProcName, szProc) == 0) {
							// wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", szProc, adwProcesses[i]);
							// return by reference
							*pdwPid = adwProcesses[i];
							*phProcess = hProcess;
							break;
						}
					}
				}

				CloseHandle(hProcess);
			}
		}
	}

	// Check if pdwPid or phProcess are NULL
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}



BOOL PrintProcesses() {

	DWORD		adwProcesses[1024 * 2],
		dwReturnLen1 = NULL,
		dwReturnLen2 = NULL,
		dwNmbrOfPids = NULL;

	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	// get the array of pid's in the system
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// calculating the number of elements in the array returned 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// a small check
		if (adwProcesses[i] != NULL) {

			// opening a process handle 
			if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// if EnumProcessModules succeeded
					// get the name of 'hProcess', and saving it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// printing the process name & its pid
						wprintf(L"[%0.3d] Process \"%s\" - Of Pid : %d \n", i, szProc, adwProcesses[i]);
					}
				}

				// close process handle 
				CloseHandle(hProcess);
			}
		}

		// Iterate through the PIDs array  
	}

	return TRUE;
}