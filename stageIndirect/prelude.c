#include <Windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"

HMODULE GetMod(DWORD modName) {

    HMODULE hModule = NULL;

    
    hModule = GetModuleHandleH(modName);
    if (hModule == NULL) {
        PRINTA("[GetModuleHandleH] failed to get the module handle, error: %d\n", GetLastError());
        return FALSE;
    }
    PRINTA("got a handle to 0x%lu!\n", modName);

    return hModule;
}



//
//  get the address of the syscall function and the SSN. Compare opcodes array at the end.
//
VOID indirectMyAss(IN DWORD funcName, IN HMODULE hNTDLL, OUT DWORD* SSN, OUT UINT_PTR* Syscall) {

    BYTE opcodes[2] = { 0x0F, 0x05 };
    UINT_PTR funcAddress = 0;


    PRINTA("starting indirectMyAss...\n");
    PRINTA("getting the address of %lu...\n", funcName);
    funcAddress = (UINT_PTR)GetProcAddressH(hNTDLL, funcName);
    if (funcAddress == NULL) {
        PRINTA("[GetProcAddress] failed to get %lu address, error: 0x%lx\n", funcName, GetLastError());
        return EXIT_FAILURE;
    }
    PRINTA("[GetProcAddress] Got the address of %lu. ADDRESS - [0x%p]\n", funcName, funcAddress);



    *SSN = ((PBYTE)(funcAddress + 4))[0];
    *Syscall = funcAddress + 0x12;


    if (_memcpy(opcodes, (const void*)*Syscall, sizeof(opcodes)) == 0) {
        PRINTA("[memcmp] function opcodes do not match the syscall opcodes, error: %d\n", GetLastError());
    }
    PRINTA("syscall signature [0x0F, 0x05] matched, found a valid syscall \n");


    PRINTA("got the SSN of %lu (0x%lx)\n", funcName, *SSN);
    PRINTA("\n\t* %lu", funcName);
    PRINTA("\n\t= Address\n\t-> [0x%p]\n\t= Syscall\n\t-> [0x%p]\n\t= SSN\n\t-> [0x%lx]\n\n", funcAddress, *Syscall, *SSN);
}