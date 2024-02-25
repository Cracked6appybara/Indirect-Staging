#include <Windows.h>
#include <stdio.h>


#include "Common.h"

HMODULE GetMod(LPCWSTR modName) {

    HMODULE hModule = NULL;


    hModule = GetModuleHandleReplacement(modName);
    if (hModule == NULL) {
        warn("[GetModuleHandle] failed to get the module handle, error: %d", GetLastError());
        return FALSE;
    }
    okay("got a handle to %S!", modName);

    return hModule;
}



//
//  get the address of the syscall function and the SSN. Compare opcodes array at the end.
//
VOID indirectMyAss(IN LPCSTR funcName, IN HMODULE hNTDLL, OUT DWORD* SSN, OUT UINT_PTR* Syscall) {

    BYTE opcodes[2] = { 0x0F, 0x05 };
    UINT_PTR funcAddress = 0;


    info("starting indirectMyAss...");
    info("getting the address of %s...", funcName);
    funcAddress = (UINT_PTR)GetProcAddressReplacement(hNTDLL, funcName);
    if (funcAddress == NULL) {
        warn("[GetProcAddress] failed to get %s address, error: 0x%lx\n", funcName, GetLastError());
        return NULL;
    }
    okay("[GetProcAddress] Got the address of %s. ADDRESS - [0x%p]", funcName, funcAddress);



    *SSN = ((PBYTE)(funcAddress + 4))[0];
    *Syscall = funcAddress + 0x12;


    if (!memcmp(opcodes, (const void*)*Syscall, sizeof(opcodes)) == 0) {
        warn("[memcmp] function opcodes do not match the syscall opcodes, error: %d", GetLastError());
    }
    okay("syscall signature [0x0F, 0x05] matched, found a valid syscall signature");


    okay("got the SSN of %s (0x%lx)", funcName, *SSN);
    printf("\n\t* %s", funcName);
    printf("\n\t= Address\n\t-> [0x%p]\n\t= Syscall\n\t-> [0x%p]\n\t= SSN\n\t-> [0x%lx]\n\n", funcAddress, *Syscall, *SSN);
}