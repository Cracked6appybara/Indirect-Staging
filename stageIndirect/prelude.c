#include <Windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"

HMODULE GetMod(DWORD modName) {

    HMODULE hModule = NULL;

    
    hModule = GetModuleHandleH(modName);
    if (hModule == NULL) {
#ifdef DEBUG
        PRINTA("[GetModuleHandleH] failed to get the module handle, error: %d\n", GetLastError());
#endif
        return FALSE;
    }
#ifdef DEBUG
    PRINTA("got a handle to 0x%lu!\n", modName);
#endif

    return hModule;
}



//
//  get the address of the syscall function and the SSN. Compare opcodes array at the end.
//
VOID indirectMyAss(IN DWORD funcName, IN HMODULE hNTDLL, OUT DWORD* SSN, OUT UINT_PTR* Syscall) {

    BYTE opcodes[2] = { 0x0F, 0x05 };
    UINT_PTR funcAddress = 0;

#ifdef DEBUG
    PRINTA("starting indirectMyAss...\n");
    PRINTA("getting the address of %lu...\n", funcName);
#endif
    funcAddress = (UINT_PTR)GetProcAddressH(hNTDLL, funcName);
    if (funcAddress == NULL) {
#ifdef DEBUG
        PRINTA("[GetProcAddress] failed to get %lu address, error: 0x%lx\n", funcName, GetLastError());
#endif
        return EXIT_FAILURE;
    }
#ifdef DEBUG
    PRINTA("[GetProcAddress] Got the address of %lu. ADDRESS - [0x%p]\n", funcName, funcAddress);
#endif



    *SSN = ((PBYTE)(funcAddress + 4))[0];
    *Syscall = funcAddress + 0x12;


    if (memcmp(opcodes, (const void*)*Syscall, sizeof(opcodes)) == 0) {
#ifdef DEBUG
        PRINTA("[memcmp] function opcodes do not match the syscall opcodes, error: %d\n", GetLastError());
#endif
    }
#ifdef DEBUG
    PRINTA("syscall signature [0x0F, 0x05] matched, found a valid syscall \n");
#endif

#ifdef DEBUG
    PRINTA("got the SSN of %lu (0x%lx)\n", funcName, *SSN);
    PRINTA("\n\t* %lu", funcName);
    PRINTA("\n\t= Address\n\t-> [0x%p]\n\t= Syscall\n\t-> [0x%p]\n\t= SSN\n\t-> [0x%lx]\n\n", funcAddress, *Syscall, *SSN);
#endif
}